// Package ddbfake is an in-memory DynamoDB for tests and write-cost
// measurement. It understands the expression subset TrailTool uses, enforces
// the 400 KB item limit, and meters capacity the way DynamoDB bills it:
//
//   - a write costs ceil(max(size before, size after) / 1 KB) write units,
//     doubled inside a transaction, and a failed condition still costs the
//     write;
//   - a read costs ceil(size / 4 KB) read units, halved when eventually
//     consistent, and reading a missing item still costs the minimum.
//
// Item size follows DynamoDB's documented rules (attribute names plus values,
// numbers at roughly one byte per two digits, 3 bytes of overhead per map or
// list and 1 byte per element).
package ddbfake

import (
	"context"
	"fmt"
	"math"
	"sort"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/smithy-go"
)

// MaxItemSize is DynamoDB's item size limit.
const MaxItemSize = 400 * 1024

// MaxExpressionLength is DynamoDB's limit on one expression string.
const MaxExpressionLength = 4096

// KeySchema names a table's hash and (optional) range attributes.
type KeySchema struct {
	Hash  string
	Range string
}

// TableStats is the metered usage of one table.
type TableStats struct {
	WriteUnits   float64
	ReadUnits    float64
	WriteCalls   int
	ReadCalls    int
	FailedWrites int // ValidationException: item too large
	Items        int
	MaxItemSize  int
	TotalSize    int
}

type table struct {
	schema KeySchema
	items  map[string]map[string]ddbtypes.AttributeValue
	sizes  map[string]int                 // item size by key
	byHash map[string]map[string]struct{} // hash key value → item keys
	stats  TableStats
}

func (t *table) put(k string, item map[string]ddbtypes.AttributeValue) {
	if item == nil {
		t.del(k)
		return
	}
	t.items[k] = item
	t.sizes[k] = ItemSize(item)
	h := scalarString(item[t.schema.Hash])
	if t.byHash[h] == nil {
		t.byHash[h] = make(map[string]struct{})
	}
	t.byHash[h][k] = struct{}{}
}

func (t *table) del(k string) {
	if item, ok := t.items[k]; ok {
		h := scalarString(item[t.schema.Hash])
		delete(t.byHash[h], k)
	}
	delete(t.items, k)
	delete(t.sizes, k)
}

// Store is the fake. The zero value is not usable; call New.
type Store struct {
	mu     sync.Mutex
	tables map[string]*table
}

// New returns an empty store with the given tables.
func New(schemas map[string]KeySchema) *Store {
	s := &Store{tables: make(map[string]*table)}
	for name, schema := range schemas {
		s.tables[name] = &table{
			schema: schema,
			items:  make(map[string]map[string]ddbtypes.AttributeValue),
			sizes:  make(map[string]int),
			byHash: make(map[string]map[string]struct{}),
		}
	}
	return s
}

// Stats reports usage per table, with item counts and sizes as of now.
func (s *Store) Stats() map[string]TableStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]TableStats, len(s.tables))
	for name, t := range s.tables {
		st := t.stats
		st.Items = len(t.items)
		st.MaxItemSize = 0
		st.TotalSize = 0
		for _, size := range t.sizes {
			st.TotalSize += size
			if size > st.MaxItemSize {
				st.MaxItemSize = size
			}
		}
		out[name] = st
	}
	return out
}

// ResetMeters zeroes the capacity counters, keeping the data.
func (s *Store) ResetMeters() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range s.tables {
		t.stats = TableStats{}
	}
}

// Items returns a copy of every item in a table.
func (s *Store) Items(tableName string) []map[string]ddbtypes.AttributeValue {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tables[tableName]
	if t == nil {
		return nil
	}
	keys := make([]string, 0, len(t.items))
	for k := range t.items {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]ddbtypes.AttributeValue, 0, len(keys))
	for _, k := range keys {
		out = append(out, copyItem(t.items[k]))
	}
	return out
}

// Get returns a copy of one item, or nil.
func (s *Store) Get(tableName string, key map[string]ddbtypes.AttributeValue) map[string]ddbtypes.AttributeValue {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tables[tableName]
	if t == nil {
		return nil
	}
	k, err := t.key(key)
	if err != nil || t.items[k] == nil {
		return nil
	}
	return copyItem(t.items[k])
}

// Seed stores an item directly, without metering.
func (s *Store) Seed(tableName string, item map[string]ddbtypes.AttributeValue) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.table(&tableName)
	if err != nil {
		return err
	}
	k, err := t.key(item)
	if err != nil {
		return err
	}
	t.put(k, copyItem(item))
	return nil
}

func (s *Store) table(name *string) (*table, error) {
	t := s.tables[aws.ToString(name)]
	if t == nil {
		return nil, &ddbtypes.ResourceNotFoundException{Message: aws.String("table not found: " + aws.ToString(name))}
	}
	return t, nil
}

func (t *table) key(item map[string]ddbtypes.AttributeValue) (string, error) {
	h, ok := item[t.schema.Hash]
	if !ok {
		return "", validation("missing hash key " + t.schema.Hash)
	}
	k := scalarString(h)
	if t.schema.Range != "" {
		r, ok := item[t.schema.Range]
		if !ok {
			return "", validation("missing range key " + t.schema.Range)
		}
		k += "\x00" + scalarString(r)
	}
	return k, nil
}

func (t *table) keyOnly(item map[string]ddbtypes.AttributeValue) map[string]ddbtypes.AttributeValue {
	out := map[string]ddbtypes.AttributeValue{t.schema.Hash: item[t.schema.Hash]}
	if t.schema.Range != "" {
		out[t.schema.Range] = item[t.schema.Range]
	}
	return out
}

func scalarString(v ddbtypes.AttributeValue) string {
	switch x := v.(type) {
	case *ddbtypes.AttributeValueMemberS:
		return "S" + x.Value
	case *ddbtypes.AttributeValueMemberN:
		return "N" + x.Value
	case *ddbtypes.AttributeValueMemberB:
		return "B" + string(x.Value)
	}
	return fmt.Sprintf("%T", v)
}

func validation(msg string) error {
	return &smithy.GenericAPIError{Code: "ValidationException", Message: msg}
}

func writeUnits(before, after int) float64 {
	size := before
	if after > size {
		size = after
	}
	return math.Max(1, math.Ceil(float64(size)/1024))
}

func readUnits(size int, consistent bool) float64 {
	u := math.Max(1, math.Ceil(float64(size)/4096))
	if !consistent {
		u /= 2
	}
	return u
}

func (t *table) charge(before, after int, factor float64) {
	t.stats.WriteUnits += factor * writeUnits(before, after)
	t.stats.WriteCalls++
}

func checkSize(t *table, size int) error {
	if size > MaxItemSize {
		t.stats.FailedWrites++
		return validation("Item size has exceeded the maximum allowed size")
	}
	return nil
}

// GetItem implements the DynamoDB API.
func (s *Store) GetItem(_ context.Context, in *dynamodb.GetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.table(in.TableName)
	if err != nil {
		return nil, err
	}
	k, err := t.key(in.Key)
	if err != nil {
		return nil, err
	}
	item := t.items[k]
	t.stats.ReadUnits += readUnits(t.sizes[k], aws.ToBool(in.ConsistentRead))
	t.stats.ReadCalls++
	if item == nil {
		return &dynamodb.GetItemOutput{}, nil
	}
	// Stored items are never mutated in place (updates replace them), so
	// readers can share them.
	return &dynamodb.GetItemOutput{Item: item}, nil
}

// BatchGetItem implements the DynamoDB API. It never returns unprocessed keys.
func (s *Store) BatchGetItem(_ context.Context, in *dynamodb.BatchGetItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.BatchGetItemOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := &dynamodb.BatchGetItemOutput{Responses: map[string][]map[string]ddbtypes.AttributeValue{}}
	for name, req := range in.RequestItems {
		t, err := s.table(aws.String(name))
		if err != nil {
			return nil, err
		}
		for _, key := range req.Keys {
			k, err := t.key(key)
			if err != nil {
				return nil, err
			}
			item := t.items[k]
			t.stats.ReadUnits += readUnits(t.sizes[k], aws.ToBool(req.ConsistentRead))
			if item != nil {
				out.Responses[name] = append(out.Responses[name], item)
			}
		}
		t.stats.ReadCalls++
	}
	return out, nil
}

// PutItem implements the DynamoDB API.
func (s *Store) PutItem(_ context.Context, in *dynamodb.PutItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.table(in.TableName)
	if err != nil {
		return nil, err
	}
	k, err := t.key(in.Item)
	if err != nil {
		return nil, err
	}
	old := t.items[k]
	ok, err := evalCondition(old, in.ConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
	if err != nil {
		return nil, err
	}
	if !ok {
		t.charge(t.sizes[k], 0, 1)
		return nil, &ddbtypes.ConditionalCheckFailedException{Message: aws.String("The conditional request failed")}
	}
	size := ItemSize(in.Item)
	if err := checkSize(t, size); err != nil {
		return nil, err
	}
	t.charge(t.sizes[k], size, 1)
	t.put(k, copyItem(in.Item))
	out := &dynamodb.PutItemOutput{}
	if in.ReturnValues == ddbtypes.ReturnValueAllOld && old != nil {
		out.Attributes = copyItem(old)
	}
	return out, nil
}

// DeleteItem implements the DynamoDB API.
func (s *Store) DeleteItem(_ context.Context, in *dynamodb.DeleteItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.table(in.TableName)
	if err != nil {
		return nil, err
	}
	k, err := t.key(in.Key)
	if err != nil {
		return nil, err
	}
	old := t.items[k]
	ok, err := evalCondition(old, in.ConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
	if err != nil {
		return nil, err
	}
	t.charge(t.sizes[k], 0, 1)
	if !ok {
		return nil, &ddbtypes.ConditionalCheckFailedException{Message: aws.String("The conditional request failed")}
	}
	t.del(k)
	return &dynamodb.DeleteItemOutput{}, nil
}

// UpdateItem implements the DynamoDB API.
func (s *Store) UpdateItem(_ context.Context, in *dynamodb.UpdateItemInput, _ ...func(*dynamodb.Options)) (*dynamodb.UpdateItemOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.table(in.TableName)
	if err != nil {
		return nil, err
	}
	old, next, err := s.update(t, in.Key, in.UpdateExpression, in.ConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues, 1)
	if err != nil {
		return nil, err
	}
	out := &dynamodb.UpdateItemOutput{}
	switch in.ReturnValues {
	case ddbtypes.ReturnValueAllOld, ddbtypes.ReturnValueUpdatedOld:
		if old != nil {
			out.Attributes = old
		}
	case ddbtypes.ReturnValueAllNew, ddbtypes.ReturnValueUpdatedNew:
		out.Attributes = next
	}
	return out, nil
}

func (s *Store) update(t *table, key map[string]ddbtypes.AttributeValue, expr, condition *string, names map[string]string, values map[string]ddbtypes.AttributeValue, factor float64) (old, next map[string]ddbtypes.AttributeValue, err error) {
	if len(aws.ToString(expr)) > MaxExpressionLength || len(aws.ToString(condition)) > MaxExpressionLength {
		return nil, nil, validation("Invalid UpdateExpression: Expression size has exceeded the maximum allowed size")
	}
	k, err := t.key(key)
	if err != nil {
		return nil, nil, err
	}
	old = t.items[k]
	ok, err := evalCondition(old, condition, names, values)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		t.charge(t.sizes[k], 0, factor)
		return nil, nil, &ddbtypes.ConditionalCheckFailedException{Message: aws.String("The conditional request failed")}
	}
	next = copyItem(old)
	if next == nil {
		next = copyItem(key)
	}
	if expr != nil {
		if err := applyUpdate(next, *expr, names, values); err != nil {
			return nil, nil, err
		}
	}
	size := ItemSize(next)
	if err := checkSize(t, size); err != nil {
		return nil, nil, err
	}
	t.charge(t.sizes[k], size, factor)
	t.put(k, next)
	return old, next, nil
}

// TransactWriteItems implements the DynamoDB API: every condition is checked
// first, and nothing is written unless all pass.
func (s *Store) TransactWriteItems(_ context.Context, in *dynamodb.TransactWriteItemsInput, _ ...func(*dynamodb.Options)) (*dynamodb.TransactWriteItemsOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reasons := make([]ddbtypes.CancellationReason, len(in.TransactItems))
	failed := false
	type staged struct {
		t    *table
		k    string
		next map[string]ddbtypes.AttributeValue // nil deletes
		old  map[string]ddbtypes.AttributeValue
	}
	var plan []staged
	for i, ti := range in.TransactItems {
		var (
			t         *table
			key       map[string]ddbtypes.AttributeValue
			condition *string
			names     map[string]string
			values    map[string]ddbtypes.AttributeValue
			err       error
		)
		switch {
		case ti.Put != nil:
			t, err = s.table(ti.Put.TableName)
			key, condition, names, values = ti.Put.Item, ti.Put.ConditionExpression, ti.Put.ExpressionAttributeNames, ti.Put.ExpressionAttributeValues
		case ti.Update != nil:
			t, err = s.table(ti.Update.TableName)
			key, condition, names, values = ti.Update.Key, ti.Update.ConditionExpression, ti.Update.ExpressionAttributeNames, ti.Update.ExpressionAttributeValues
		case ti.Delete != nil:
			t, err = s.table(ti.Delete.TableName)
			key, condition, names, values = ti.Delete.Key, ti.Delete.ConditionExpression, ti.Delete.ExpressionAttributeNames, ti.Delete.ExpressionAttributeValues
		case ti.ConditionCheck != nil:
			t, err = s.table(ti.ConditionCheck.TableName)
			key, condition, names, values = ti.ConditionCheck.Key, ti.ConditionCheck.ConditionExpression, ti.ConditionCheck.ExpressionAttributeNames, ti.ConditionCheck.ExpressionAttributeValues
		}
		if err != nil {
			return nil, err
		}
		k, err := t.key(key)
		if err != nil {
			return nil, err
		}
		old := t.items[k]
		ok, err := evalCondition(old, condition, names, values)
		if err != nil {
			return nil, err
		}
		reasons[i] = ddbtypes.CancellationReason{Code: aws.String("None")}
		if !ok {
			reasons[i] = ddbtypes.CancellationReason{Code: aws.String("ConditionalCheckFailed")}
			failed = true
			continue
		}
		st := staged{t: t, k: k, old: old}
		switch {
		case ti.Put != nil:
			st.next = copyItem(ti.Put.Item)
		case ti.Update != nil:
			st.next = copyItem(old)
			if st.next == nil {
				st.next = copyItem(ti.Update.Key)
			}
			if err := applyUpdate(st.next, aws.ToString(ti.Update.UpdateExpression), names, values); err != nil {
				return nil, err
			}
		case ti.ConditionCheck != nil:
			st.next = old
		}
		if st.next != nil && ItemSize(st.next) > MaxItemSize {
			t.stats.FailedWrites++
			return nil, validation("Item size has exceeded the maximum allowed size")
		}
		plan = append(plan, st)
	}
	// A transaction is billed for every item it names, whether or not it
	// commits.
	for _, ti := range in.TransactItems {
		var t *table
		var key map[string]ddbtypes.AttributeValue
		switch {
		case ti.Put != nil:
			t, _ = s.table(ti.Put.TableName)
			key = ti.Put.Item
		case ti.Update != nil:
			t, _ = s.table(ti.Update.TableName)
			key = ti.Update.Key
		case ti.Delete != nil:
			t, _ = s.table(ti.Delete.TableName)
			key = ti.Delete.Key
		case ti.ConditionCheck != nil:
			t, _ = s.table(ti.ConditionCheck.TableName)
			key = ti.ConditionCheck.Key
		}
		k, _ := t.key(key)
		before := t.sizes[k]
		after := before
		for _, st := range plan {
			if st.t == t && st.k == k && !failed {
				after = ItemSize(st.next)
			}
		}
		if ti.ConditionCheck != nil {
			t.stats.ReadUnits += 2 * readUnits(before, true)
			continue
		}
		t.charge(before, after, 2)
	}
	if failed {
		return nil, &ddbtypes.TransactionCanceledException{
			Message:             aws.String("Transaction cancelled"),
			CancellationReasons: reasons,
		}
	}
	for _, st := range plan {
		if st.next == nil {
			st.t.del(st.k)
		} else {
			st.t.put(st.k, st.next)
		}
	}
	return &dynamodb.TransactWriteItemsOutput{}, nil
}

// Query implements the DynamoDB API by evaluating the key condition against
// every item, ordered by range key. IndexName queries match items that carry
// the attributes the condition names; they sort by the condition's own order.
func (s *Store) Query(_ context.Context, in *dynamodb.QueryInput, _ ...func(*dynamodb.Options)) (*dynamodb.QueryOutput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, err := s.table(in.TableName)
	if err != nil {
		return nil, err
	}
	var matched []map[string]ddbtypes.AttributeValue
	candidates := t.items
	if keys, ok := t.hashCandidates(in); ok {
		candidates = make(map[string]map[string]ddbtypes.AttributeValue, len(keys))
		for k := range keys {
			candidates[k] = t.items[k]
		}
	}
	for _, item := range candidates {
		ok, err := evalCondition(item, in.KeyConditionExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
		if err != nil {
			return nil, err
		}
		if ok {
			matched = append(matched, item)
		}
	}
	sortKey := t.schema.Range
	sort.Slice(matched, func(i, j int) bool {
		a, b := matched[i][sortKey], matched[j][sortKey]
		if c, ok := compare(a, b); ok && c != 0 {
			if in.ScanIndexForward != nil && !*in.ScanIndexForward {
				return c > 0
			}
			return c < 0
		}
		ki, _ := t.key(matched[i])
		kj, _ := t.key(matched[j])
		return ki < kj
	})
	size := 0
	out := &dynamodb.QueryOutput{}
	for _, item := range matched {
		k, _ := t.key(item)
		size += t.sizes[k]
		ok, err := evalCondition(item, in.FilterExpression, in.ExpressionAttributeNames, in.ExpressionAttributeValues)
		if err != nil {
			return nil, err
		}
		if ok {
			out.Items = append(out.Items, item)
		}
		if in.Limit != nil && int32(len(out.Items)) >= *in.Limit {
			break
		}
	}
	out.Count = int32(len(out.Items))
	t.stats.ReadUnits += readUnits(size, aws.ToBool(in.ConsistentRead))
	t.stats.ReadCalls++
	return out, nil
}

// hashCandidates narrows a base-table query whose key condition begins with
// "<hash attribute> = :value" to that partition's items.
func (t *table) hashCandidates(in *dynamodb.QueryInput) (map[string]struct{}, bool) {
	if in.IndexName != nil {
		return nil, false
	}
	toks, err := tokenize(aws.ToString(in.KeyConditionExpression))
	if err != nil || len(toks) < 3 || toks[1].text != "=" || toks[2].kind != "value" {
		return nil, false
	}
	name := toks[0].text
	if toks[0].kind == "name" {
		name = in.ExpressionAttributeNames[name]
	}
	if name != t.schema.Hash {
		return nil, false
	}
	v, ok := in.ExpressionAttributeValues[toks[2].text]
	if !ok {
		return nil, false
	}
	return t.byHash[scalarString(v)], true
}

// ItemSize approximates DynamoDB's billed size of an item.
func ItemSize(item map[string]ddbtypes.AttributeValue) int {
	if item == nil {
		return 0
	}
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
		digits, leading := 0, true
		for i := 0; i < len(x.Value); i++ {
			c := x.Value[i]
			if c < '0' || c > '9' || (leading && c == '0') {
				continue
			}
			leading = false
			digits++
		}
		return (digits+1)/2 + 1
	case *ddbtypes.AttributeValueMemberB:
		return len(x.Value)
	case *ddbtypes.AttributeValueMemberBOOL, *ddbtypes.AttributeValueMemberNULL:
		return 1
	case *ddbtypes.AttributeValueMemberSS:
		n := 0
		for _, s := range x.Value {
			n += len(s)
		}
		return n
	case *ddbtypes.AttributeValueMemberNS:
		n := 0
		for _, s := range x.Value {
			n += valueSize(&ddbtypes.AttributeValueMemberN{Value: s})
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

func copyItem(item map[string]ddbtypes.AttributeValue) map[string]ddbtypes.AttributeValue {
	if item == nil {
		return nil
	}
	out := make(map[string]ddbtypes.AttributeValue, len(item))
	for k, v := range item {
		out[k] = deepCopy(v)
	}
	return out
}

func deepCopy(v ddbtypes.AttributeValue) ddbtypes.AttributeValue {
	switch x := v.(type) {
	case *ddbtypes.AttributeValueMemberM:
		return &ddbtypes.AttributeValueMemberM{Value: copyItem(x.Value)}
	case *ddbtypes.AttributeValueMemberL:
		out := make([]ddbtypes.AttributeValue, len(x.Value))
		for i, e := range x.Value {
			out[i] = deepCopy(e)
		}
		return &ddbtypes.AttributeValueMemberL{Value: out}
	case *ddbtypes.AttributeValueMemberSS:
		return &ddbtypes.AttributeValueMemberSS{Value: append([]string(nil), x.Value...)}
	case *ddbtypes.AttributeValueMemberS:
		return &ddbtypes.AttributeValueMemberS{Value: x.Value}
	case *ddbtypes.AttributeValueMemberN:
		return &ddbtypes.AttributeValueMemberN{Value: x.Value}
	}
	return v
}
