// Package ddbfake is a small in-memory DynamoDB table for tests of
// UpdateItem-based write paths. Nothing outside tests imports it.
//
// It supports GetItem and UpdateItem with the expression subset those paths
// use: SET (value or if_not_exists), ADD (number or string set), and REMOVE
// on top-level attributes, and conditions built from AND, OR, parentheses,
// attribute_exists, attribute_not_exists, and comparisons (= and <> on any
// type, < <= > >= on strings and numbers). It enforces
// the 400 KB item limit and meters write units the way DynamoDB bills them:
// ceil(max(size before, size after) / 1 KB), failed conditions included.
package ddbfake

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"strings"
	"sync"
	"unicode"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
)

// MaxItemSize is DynamoDB's item size limit.
const MaxItemSize = 400 * 1024

// Item is one stored item.
type Item = map[string]ddbtypes.AttributeValue

// Store holds the tables named in New, each keyed by (hash, range).
type Store struct {
	mu     sync.Mutex
	keys   map[string][2]string       // table → hash and range attribute names
	tables map[string]map[string]Item // table → key → item
	wcu    map[string]float64         // table → write units

	// FailUpdate, when set, is consulted before every UpdateItem, outside
	// the store's lock (so it may call Seed to simulate a concurrent writer);
	// a non-nil error fails the call without changing anything.
	FailUpdate func(*dynamodb.UpdateItemInput) error
	// StaleGet, when set and returning true for an eventually consistent
	// GetItem, answers that read with the returned item (nil for none), as a
	// lagging replica can.
	StaleGet func(*dynamodb.GetItemInput) (Item, bool)
}

// New returns a store whose tables have the given hash and range attributes.
func New(tables map[string][2]string) *Store {
	s := &Store{keys: tables, tables: map[string]map[string]Item{}, wcu: map[string]float64{}}
	for name := range tables {
		s.tables[name] = map[string]Item{}
	}
	return s
}

func (s *Store) key(table string, item Item) (string, error) {
	names, ok := s.keys[table]
	if !ok {
		return "", fmt.Errorf("no table %q", table)
	}
	var b strings.Builder
	for _, n := range names {
		v, ok := item[n].(*ddbtypes.AttributeValueMemberS)
		if !ok {
			return "", validation("missing key attribute " + n)
		}
		b.WriteString(v.Value)
		b.WriteByte(0)
	}
	return b.String(), nil
}

// Seed stores an item without metering.
func (s *Store) Seed(table string, item Item) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, err := s.key(table, item)
	if err != nil {
		return err
	}
	s.tables[table][k] = copyItem(item)
	return nil
}

// Get returns a copy of one item, or nil.
func (s *Store) Get(table string, key Item) Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, err := s.key(table, key)
	if err != nil {
		return nil
	}
	return copyItem(s.tables[table][k])
}

// Items returns copies of every item in a table.
func (s *Store) Items(table string) []Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Item
	for _, item := range s.tables[table] {
		out = append(out, copyItem(item))
	}
	return out
}

// WriteUnits returns the write units a table has been billed.
func (s *Store) WriteUnits(table string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.wcu[table]
}

// GetItem implements the DynamoDB API (projections are ignored).
func (s *Store) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	if s.StaleGet != nil && !aws.ToBool(in.ConsistentRead) {
		if item, ok := s.StaleGet(in); ok {
			return &dynamodb.GetItemOutput{Item: copyItem(item)}, nil
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	table := aws.ToString(in.TableName)
	k, err := s.key(table, in.Key)
	if err != nil {
		return nil, err
	}
	return &dynamodb.GetItemOutput{Item: copyItem(s.tables[table][k])}, nil
}

// UpdateItem implements the DynamoDB API.
func (s *Store) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	if s.FailUpdate != nil {
		if err := s.FailUpdate(in); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	table := aws.ToString(in.TableName)
	k, err := s.key(table, in.Key)
	if err != nil {
		return nil, err
	}
	old := s.tables[table][k]
	e := &evaluator{names: in.ExpressionAttributeNames, values: in.ExpressionAttributeValues}
	if in.ConditionExpression != nil {
		ok, err := e.condition(*in.ConditionExpression, old)
		if err != nil {
			return nil, err
		}
		if !ok {
			s.wcu[table] += units(ItemSize(old), 0)
			return nil, &ddbtypes.ConditionalCheckFailedException{Message: aws.String("The conditional request failed")}
		}
	}
	next := copyItem(old)
	if next == nil {
		next = copyItem(in.Key)
	}
	if err := e.update(aws.ToString(in.UpdateExpression), old, next); err != nil {
		return nil, err
	}
	if ItemSize(next) > MaxItemSize {
		return nil, validation("Item size has exceeded the maximum allowed size")
	}
	s.wcu[table] += units(ItemSize(old), ItemSize(next))
	s.tables[table][k] = next
	out := &dynamodb.UpdateItemOutput{}
	if in.ReturnValues == ddbtypes.ReturnValueAllOld {
		out.Attributes = copyItem(old)
	}
	return out, nil
}

func units(before, after int) float64 {
	return math.Max(1, math.Ceil(float64(max(before, after))/1024))
}

func validation(msg string) error {
	return &smithy.GenericAPIError{Code: "ValidationException", Message: msg}
}

// evaluator interprets expressions against one request's placeholders.
type evaluator struct {
	names  map[string]string
	values map[string]ddbtypes.AttributeValue
	toks   []string
	pos    int
}

func tokenize(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		c := rune(s[i])
		switch {
		case unicode.IsSpace(c):
			i++
		case strings.HasPrefix(s[i:], "<="), strings.HasPrefix(s[i:], ">="), strings.HasPrefix(s[i:], "<>"):
			out = append(out, s[i:i+2])
			i += 2
		case strings.ContainsRune("(),=<>", c):
			out = append(out, string(c))
			i++
		default:
			j := i
			for j < len(s) && !unicode.IsSpace(rune(s[j])) && !strings.ContainsRune("(),=<>", rune(s[j])) {
				j++
			}
			out = append(out, s[i:j])
			i = j
		}
	}
	return out
}

func (e *evaluator) next() string {
	if e.pos >= len(e.toks) {
		return ""
	}
	t := e.toks[e.pos]
	e.pos++
	return t
}

func (e *evaluator) peek() string {
	if e.pos >= len(e.toks) {
		return ""
	}
	return e.toks[e.pos]
}

func (e *evaluator) attr(tok string) (string, error) {
	if strings.HasPrefix(tok, "#") {
		n, ok := e.names[tok]
		if !ok {
			return "", fmt.Errorf("undefined name %s", tok)
		}
		return n, nil
	}
	if tok == "" || strings.HasPrefix(tok, ":") {
		return "", fmt.Errorf("expected attribute, got %q", tok)
	}
	return tok, nil
}

// operand reads a placeholder value or an attribute of item (nil if absent).
func (e *evaluator) operand(item Item) (ddbtypes.AttributeValue, error) {
	tok := e.next()
	if strings.HasPrefix(tok, ":") {
		v, ok := e.values[tok]
		if !ok {
			return nil, fmt.Errorf("undefined value %s", tok)
		}
		return v, nil
	}
	if tok == "if_not_exists" {
		e.next() // (
		a, err := e.attr(e.next())
		if err != nil {
			return nil, err
		}
		e.next() // ,
		def, err := e.operand(item)
		if err != nil {
			return nil, err
		}
		e.next() // )
		if v, ok := item[a]; ok {
			return v, nil
		}
		return def, nil
	}
	a, err := e.attr(tok)
	if err != nil {
		return nil, err
	}
	return item[a], nil
}

func (e *evaluator) update(expr string, old, next Item) error {
	e.toks, e.pos = tokenize(expr), 0
	clause := ""
	for e.peek() != "" {
		switch t := strings.ToUpper(e.peek()); t {
		case "SET", "ADD", "REMOVE":
			clause = t
			e.next()
			continue
		case ",":
			e.next()
			continue
		}
		a, err := e.attr(e.next())
		if err != nil {
			return err
		}
		switch clause {
		case "SET":
			if e.next() != "=" {
				return fmt.Errorf("SET %s: expected =", a)
			}
			v, err := e.operand(old)
			if err != nil {
				return err
			}
			next[a] = v
		case "ADD":
			v, err := e.operand(old)
			if err != nil {
				return err
			}
			sum, err := add(next[a], v)
			if err != nil {
				return err
			}
			next[a] = sum
		case "REMOVE":
			delete(next, a)
		default:
			return fmt.Errorf("unsupported update expression %q", expr)
		}
	}
	return nil
}

func add(cur, v ddbtypes.AttributeValue) (ddbtypes.AttributeValue, error) {
	switch x := v.(type) {
	case *ddbtypes.AttributeValueMemberN:
		if cur == nil {
			return x, nil
		}
		c, ok := cur.(*ddbtypes.AttributeValueMemberN)
		if !ok {
			return nil, validation("ADD type mismatch")
		}
		a, _ := new(big.Float).SetString(c.Value)
		b, _ := new(big.Float).SetString(x.Value)
		return &ddbtypes.AttributeValueMemberN{Value: a.Add(a, b).Text('f', -1)}, nil
	case *ddbtypes.AttributeValueMemberSS:
		out := []string{}
		seen := map[string]bool{}
		if c, ok := cur.(*ddbtypes.AttributeValueMemberSS); ok {
			for _, s := range c.Value {
				seen[s] = true
				out = append(out, s)
			}
		}
		for _, s := range x.Value {
			if !seen[s] {
				out = append(out, s)
			}
		}
		return &ddbtypes.AttributeValueMemberSS{Value: out}, nil
	}
	return nil, validation("ADD supports numbers and string sets")
}

func (e *evaluator) condition(expr string, item Item) (bool, error) {
	e.toks, e.pos = tokenize(expr), 0
	ok, err := e.or(item)
	if err == nil && e.peek() != "" {
		err = fmt.Errorf("trailing %q in condition %q", e.peek(), expr)
	}
	return ok, err
}

func (e *evaluator) or(item Item) (bool, error) {
	left, err := e.and(item)
	for err == nil && strings.EqualFold(e.peek(), "OR") {
		e.next()
		var right bool
		right, err = e.and(item)
		left = left || right
	}
	return left, err
}

func (e *evaluator) and(item Item) (bool, error) {
	left, err := e.primary(item)
	for err == nil && strings.EqualFold(e.peek(), "AND") {
		e.next()
		var right bool
		right, err = e.primary(item)
		left = left && right
	}
	return left, err
}

func (e *evaluator) primary(item Item) (bool, error) {
	switch t := e.peek(); t {
	case "(":
		e.next()
		ok, err := e.or(item)
		e.next() // )
		return ok, err
	case "attribute_exists", "attribute_not_exists":
		e.next()
		e.next() // (
		a, err := e.attr(e.next())
		e.next() // )
		_, present := item[a]
		return present == (t == "attribute_exists"), err
	}
	left, err := e.operand(item)
	if err != nil {
		return false, err
	}
	op := e.next()
	right, err := e.operand(item)
	if err != nil {
		return false, err
	}
	if op == "=" || op == "<>" {
		// Equality works on every type, maps and lists included.
		return (left != nil && right != nil && reflect.DeepEqual(left, right)) == (op == "="), nil
	}
	c, comparable := compare(left, right)
	switch op {
	case "<":
		return comparable && c < 0, nil
	case "<=":
		return comparable && c <= 0, nil
	case ">":
		return comparable && c > 0, nil
	case ">=":
		return comparable && c >= 0, nil
	}
	return false, fmt.Errorf("unsupported comparator %q", op)
}

func compare(a, b ddbtypes.AttributeValue) (int, bool) {
	switch x := a.(type) {
	case *ddbtypes.AttributeValueMemberS:
		if y, ok := b.(*ddbtypes.AttributeValueMemberS); ok {
			return strings.Compare(x.Value, y.Value), true
		}
	case *ddbtypes.AttributeValueMemberN:
		if y, ok := b.(*ddbtypes.AttributeValueMemberN); ok {
			xf, _ := new(big.Float).SetString(x.Value)
			yf, _ := new(big.Float).SetString(y.Value)
			return xf.Cmp(yf), true
		}
	}
	return 0, false
}

// ItemSize approximates DynamoDB's billed item size: attribute names plus
// values, numbers at about one byte per two digits, 3 bytes per map or list
// plus 1 per element.
func ItemSize(item Item) int {
	n := 0
	for name, v := range item {
		n += len(name) + valueSize(v)
	}
	return n
}

func valueSize(v ddbtypes.AttributeValue) int {
	switch x := v.(type) {
	case *ddbtypes.AttributeValueMemberS:
		return len(x.Value)
	case *ddbtypes.AttributeValueMemberN:
		return (len(strings.TrimLeft(x.Value, "-0"))+1)/2 + 1
	case *ddbtypes.AttributeValueMemberBOOL, *ddbtypes.AttributeValueMemberNULL:
		return 1
	case *ddbtypes.AttributeValueMemberSS:
		n := 0
		for _, s := range x.Value {
			n += len(s)
		}
		return n
	case *ddbtypes.AttributeValueMemberL:
		n := 3
		for _, e := range x.Value {
			n += valueSize(e) + 1
		}
		return n
	case *ddbtypes.AttributeValueMemberM:
		n := 3
		for k, e := range x.Value {
			n += len(k) + valueSize(e) + 1
		}
		return n
	}
	return 0
}

// copyItem copies the top level; nested values are never mutated in place.
func copyItem(item Item) Item {
	if item == nil {
		return nil
	}
	out := make(Item, len(item))
	for k, v := range item {
		out[k] = v
	}
	return out
}
