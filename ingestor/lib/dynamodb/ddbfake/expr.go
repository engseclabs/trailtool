package ddbfake

import (
	"fmt"
	"math/big"
	"strconv"
	"strings"
	"unicode"

	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

// This file is a small interpreter for the subset of DynamoDB expression
// syntax TrailTool uses: SET/ADD/REMOVE/DELETE update clauses, if_not_exists,
// list_append, + and -, and condition expressions with AND/OR/NOT, the
// comparison operators, BETWEEN, IN, attribute_exists, attribute_not_exists,
// begins_with, contains and size.

type token struct {
	kind string // "ident", "name", "value", "num", "op"
	text string
}

func tokenize(s string) ([]token, error) {
	var out []token
	i := 0
	for i < len(s) {
		c := rune(s[i])
		switch {
		case unicode.IsSpace(c):
			i++
		case c == '#' || c == ':' || c == '_' || unicode.IsLetter(c):
			j := i + 1
			for j < len(s) && (s[j] == '_' || unicode.IsLetter(rune(s[j])) || unicode.IsDigit(rune(s[j]))) {
				j++
			}
			kind := "ident"
			if c == '#' {
				kind = "name"
			} else if c == ':' {
				kind = "value"
			}
			out = append(out, token{kind, s[i:j]})
			i = j
		case unicode.IsDigit(c):
			j := i + 1
			for j < len(s) && unicode.IsDigit(rune(s[j])) {
				j++
			}
			out = append(out, token{"num", s[i:j]})
			i = j
		default:
			two := ""
			if i+1 < len(s) {
				two = s[i : i+2]
			}
			if two == "<>" || two == "<=" || two == ">=" {
				out = append(out, token{"op", two})
				i += 2
				continue
			}
			if strings.ContainsRune("()=<>,.[]+-", c) {
				out = append(out, token{"op", string(c)})
				i++
				continue
			}
			return nil, fmt.Errorf("unexpected character %q in expression %q", c, s)
		}
	}
	return out, nil
}

type parser struct {
	toks   []token
	pos    int
	names  map[string]string
	values map[string]ddbtypes.AttributeValue
}

func (p *parser) peek() token {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return token{}
}

func (p *parser) next() token {
	t := p.peek()
	p.pos++
	return t
}

func (p *parser) keyword(k string) bool {
	t := p.peek()
	if t.kind == "ident" && strings.EqualFold(t.text, k) {
		p.pos++
		return true
	}
	return false
}

func (p *parser) op(o string) bool {
	t := p.peek()
	if t.kind == "op" && t.text == o {
		p.pos++
		return true
	}
	return false
}

func (p *parser) expectOp(o string) error {
	if !p.op(o) {
		return fmt.Errorf("expected %q at token %d (%q)", o, p.pos, p.peek().text)
	}
	return nil
}

// pathElem is one element of a document path: a map key or a list index.
type pathElem struct {
	name  string
	index int
	isIdx bool
}

type path []pathElem

func (p path) String() string {
	var b strings.Builder
	for i, e := range p {
		if e.isIdx {
			fmt.Fprintf(&b, "[%d]", e.index)
			continue
		}
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(e.name)
	}
	return b.String()
}

func (p *parser) parsePath() (path, error) {
	var out path
	readName := func() error {
		t := p.next()
		switch t.kind {
		case "name":
			n, ok := p.names[t.text]
			if !ok {
				return fmt.Errorf("undefined attribute name %s", t.text)
			}
			out = append(out, pathElem{name: n})
		case "ident":
			out = append(out, pathElem{name: t.text})
		default:
			return fmt.Errorf("expected attribute path, got %q", t.text)
		}
		return nil
	}
	if err := readName(); err != nil {
		return nil, err
	}
	for {
		if p.op(".") {
			if err := readName(); err != nil {
				return nil, err
			}
			continue
		}
		if p.op("[") {
			t := p.next()
			n, err := strconv.Atoi(t.text)
			if err != nil {
				return nil, fmt.Errorf("bad list index %q", t.text)
			}
			if err := p.expectOp("]"); err != nil {
				return nil, err
			}
			out = append(out, pathElem{index: n, isIdx: true})
			continue
		}
		return out, nil
	}
}

// operand evaluates to a value against an item; nil means "absent".
type operand func(item map[string]ddbtypes.AttributeValue) (ddbtypes.AttributeValue, error)

func (p *parser) parseOperand() (operand, error) {
	t := p.peek()
	if t.kind == "value" {
		p.pos++
		v, ok := p.values[t.text]
		if !ok {
			return nil, fmt.Errorf("undefined attribute value %s", t.text)
		}
		return func(map[string]ddbtypes.AttributeValue) (ddbtypes.AttributeValue, error) { return v, nil }, nil
	}
	if t.kind == "ident" && p.pos+1 < len(p.toks) && p.toks[p.pos+1].text == "(" {
		fn := strings.ToLower(t.text)
		p.pos += 2
		switch fn {
		case "if_not_exists":
			pa, err := p.parsePath()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(","); err != nil {
				return nil, err
			}
			def, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(")"); err != nil {
				return nil, err
			}
			return func(item map[string]ddbtypes.AttributeValue) (ddbtypes.AttributeValue, error) {
				if v := getPath(item, pa); v != nil {
					return v, nil
				}
				return def(item)
			}, nil
		case "list_append":
			a, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(","); err != nil {
				return nil, err
			}
			b, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(")"); err != nil {
				return nil, err
			}
			return func(item map[string]ddbtypes.AttributeValue) (ddbtypes.AttributeValue, error) {
				av, err := a(item)
				if err != nil {
					return nil, err
				}
				bv, err := b(item)
				if err != nil {
					return nil, err
				}
				al, ok1 := av.(*ddbtypes.AttributeValueMemberL)
				bl, ok2 := bv.(*ddbtypes.AttributeValueMemberL)
				if !ok1 || !ok2 {
					return nil, validation("list_append operands must be lists")
				}
				out := append(append([]ddbtypes.AttributeValue{}, al.Value...), bl.Value...)
				return &ddbtypes.AttributeValueMemberL{Value: out}, nil
			}, nil
		case "size":
			pa, err := p.parsePath()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(")"); err != nil {
				return nil, err
			}
			return func(item map[string]ddbtypes.AttributeValue) (ddbtypes.AttributeValue, error) {
				v := getPath(item, pa)
				n := 0
				switch x := v.(type) {
				case *ddbtypes.AttributeValueMemberS:
					n = len(x.Value)
				case *ddbtypes.AttributeValueMemberB:
					n = len(x.Value)
				case *ddbtypes.AttributeValueMemberL:
					n = len(x.Value)
				case *ddbtypes.AttributeValueMemberM:
					n = len(x.Value)
				case *ddbtypes.AttributeValueMemberSS:
					n = len(x.Value)
				case *ddbtypes.AttributeValueMemberNS:
					n = len(x.Value)
				case nil:
					return nil, nil
				}
				return &ddbtypes.AttributeValueMemberN{Value: strconv.Itoa(n)}, nil
			}, nil
		default:
			return nil, fmt.Errorf("unsupported function %s", fn)
		}
	}
	pa, err := p.parsePath()
	if err != nil {
		return nil, err
	}
	return func(item map[string]ddbtypes.AttributeValue) (ddbtypes.AttributeValue, error) {
		return getPath(item, pa), nil
	}, nil
}

func (p *parser) parseValueExpr() (operand, error) {
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	for {
		var sign int
		switch {
		case p.op("+"):
			sign = 1
		case p.op("-"):
			sign = -1
		default:
			return left, nil
		}
		right, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		l := left
		left = func(item map[string]ddbtypes.AttributeValue) (ddbtypes.AttributeValue, error) {
			a, err := l(item)
			if err != nil {
				return nil, err
			}
			b, err := right(item)
			if err != nil {
				return nil, err
			}
			an, ok1 := a.(*ddbtypes.AttributeValueMemberN)
			bn, ok2 := b.(*ddbtypes.AttributeValueMemberN)
			if !ok1 || !ok2 {
				return nil, validation("An operand in the update expression has an incorrect data type")
			}
			return addNumbers(an.Value, bn.Value, sign), nil
		}
	}
}

func addNumbers(a, b string, sign int) *ddbtypes.AttributeValueMemberN {
	x, _ := new(big.Float).SetPrec(200).SetString(a)
	y, _ := new(big.Float).SetPrec(200).SetString(b)
	if sign < 0 {
		y.Neg(y)
	}
	return &ddbtypes.AttributeValueMemberN{Value: x.Add(x, y).Text('f', -1)}
}

// cond evaluates a condition against an item.
type cond func(item map[string]ddbtypes.AttributeValue) (bool, error)

func (p *parser) parseCond() (cond, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.keyword("OR") {
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l := left
		left = func(item map[string]ddbtypes.AttributeValue) (bool, error) {
			a, err := l(item)
			if err != nil || a {
				return a, err
			}
			return right(item)
		}
	}
	return left, nil
}

func (p *parser) parseAnd() (cond, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.keyword("AND") {
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		l := left
		left = func(item map[string]ddbtypes.AttributeValue) (bool, error) {
			a, err := l(item)
			if err != nil || !a {
				return a, err
			}
			return right(item)
		}
	}
	return left, nil
}

func (p *parser) parseNot() (cond, error) {
	if p.keyword("NOT") {
		inner, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return func(item map[string]ddbtypes.AttributeValue) (bool, error) {
			v, err := inner(item)
			return !v, err
		}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (cond, error) {
	if p.op("(") {
		c, err := p.parseCond()
		if err != nil {
			return nil, err
		}
		return c, p.expectOp(")")
	}
	t := p.peek()
	if t.kind == "ident" && p.pos+1 < len(p.toks) && p.toks[p.pos+1].text == "(" {
		fn := strings.ToLower(t.text)
		switch fn {
		case "attribute_exists", "attribute_not_exists":
			p.pos += 2
			pa, err := p.parsePath()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(")"); err != nil {
				return nil, err
			}
			want := fn == "attribute_exists"
			return func(item map[string]ddbtypes.AttributeValue) (bool, error) {
				return (getPath(item, pa) != nil) == want, nil
			}, nil
		case "begins_with", "contains":
			p.pos += 2
			a, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(","); err != nil {
				return nil, err
			}
			b, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			if err := p.expectOp(")"); err != nil {
				return nil, err
			}
			return func(item map[string]ddbtypes.AttributeValue) (bool, error) {
				av, _ := a(item)
				bv, _ := b(item)
				bs, ok := bv.(*ddbtypes.AttributeValueMemberS)
				if !ok {
					return false, nil
				}
				switch x := av.(type) {
				case *ddbtypes.AttributeValueMemberS:
					if fn == "begins_with" {
						return strings.HasPrefix(x.Value, bs.Value), nil
					}
					return strings.Contains(x.Value, bs.Value), nil
				case *ddbtypes.AttributeValueMemberSS:
					for _, s := range x.Value {
						if s == bs.Value {
							return true, nil
						}
					}
				}
				return false, nil
			}, nil
		}
	}
	left, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	if p.keyword("BETWEEN") {
		lo, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		if !p.keyword("AND") {
			return nil, fmt.Errorf("BETWEEN without AND")
		}
		hi, err := p.parseOperand()
		if err != nil {
			return nil, err
		}
		return func(item map[string]ddbtypes.AttributeValue) (bool, error) {
			v, _ := left(item)
			l, _ := lo(item)
			h, _ := hi(item)
			c1, ok1 := compare(v, l)
			c2, ok2 := compare(v, h)
			return ok1 && ok2 && c1 >= 0 && c2 <= 0, nil
		}, nil
	}
	if p.keyword("IN") {
		if err := p.expectOp("("); err != nil {
			return nil, err
		}
		var opts []operand
		for {
			o, err := p.parseOperand()
			if err != nil {
				return nil, err
			}
			opts = append(opts, o)
			if !p.op(",") {
				break
			}
		}
		if err := p.expectOp(")"); err != nil {
			return nil, err
		}
		return func(item map[string]ddbtypes.AttributeValue) (bool, error) {
			v, _ := left(item)
			for _, o := range opts {
				ov, _ := o(item)
				if c, ok := compare(v, ov); ok && c == 0 {
					return true, nil
				}
			}
			return false, nil
		}, nil
	}
	t = p.next()
	if t.kind != "op" {
		return nil, fmt.Errorf("expected comparator, got %q", t.text)
	}
	cmp := t.text
	right, err := p.parseOperand()
	if err != nil {
		return nil, err
	}
	return func(item map[string]ddbtypes.AttributeValue) (bool, error) {
		a, _ := left(item)
		b, _ := right(item)
		c, ok := compare(a, b)
		switch cmp {
		case "=":
			return ok && c == 0, nil
		case "<>":
			return !ok || c != 0, nil
		case "<":
			return ok && c < 0, nil
		case "<=":
			return ok && c <= 0, nil
		case ">":
			return ok && c > 0, nil
		case ">=":
			return ok && c >= 0, nil
		}
		return false, fmt.Errorf("unknown comparator %s", cmp)
	}, nil
}

// compare orders two scalar values of the same type.
func compare(a, b ddbtypes.AttributeValue) (int, bool) {
	switch x := a.(type) {
	case *ddbtypes.AttributeValueMemberS:
		y, ok := b.(*ddbtypes.AttributeValueMemberS)
		if !ok {
			return 0, false
		}
		return strings.Compare(x.Value, y.Value), true
	case *ddbtypes.AttributeValueMemberN:
		y, ok := b.(*ddbtypes.AttributeValueMemberN)
		if !ok {
			return 0, false
		}
		xf, _ := new(big.Float).SetString(x.Value)
		yf, _ := new(big.Float).SetString(y.Value)
		return xf.Cmp(yf), true
	case *ddbtypes.AttributeValueMemberBOOL:
		y, ok := b.(*ddbtypes.AttributeValueMemberBOOL)
		if !ok {
			return 0, false
		}
		if x.Value == y.Value {
			return 0, true
		}
		return 1, true
	}
	return 0, false
}

func getPath(item map[string]ddbtypes.AttributeValue, pa path) ddbtypes.AttributeValue {
	var cur ddbtypes.AttributeValue = &ddbtypes.AttributeValueMemberM{Value: item}
	for _, e := range pa {
		switch x := cur.(type) {
		case *ddbtypes.AttributeValueMemberM:
			if e.isIdx {
				return nil
			}
			v, ok := x.Value[e.name]
			if !ok {
				return nil
			}
			cur = v
		case *ddbtypes.AttributeValueMemberL:
			if !e.isIdx || e.index >= len(x.Value) {
				return nil
			}
			cur = x.Value[e.index]
		default:
			return nil
		}
	}
	return cur
}

// setPath writes v at pa. Every parent must exist, as in DynamoDB.
func setPath(item map[string]ddbtypes.AttributeValue, pa path, v ddbtypes.AttributeValue) error {
	if len(pa) == 1 {
		item[pa[0].name] = v
		return nil
	}
	parent := getPath(item, pa[:len(pa)-1])
	last := pa[len(pa)-1]
	switch x := parent.(type) {
	case *ddbtypes.AttributeValueMemberM:
		x.Value[last.name] = v
	case *ddbtypes.AttributeValueMemberL:
		if !last.isIdx {
			return validation("The document path provided in the update expression is invalid for update")
		}
		if last.index >= len(x.Value) {
			x.Value = append(x.Value, v)
		} else {
			x.Value[last.index] = v
		}
	default:
		return validation("The document path provided in the update expression is invalid for update")
	}
	return nil
}

func removePath(item map[string]ddbtypes.AttributeValue, pa path) {
	if len(pa) == 1 {
		delete(item, pa[0].name)
		return
	}
	if m, ok := getPath(item, pa[:len(pa)-1]).(*ddbtypes.AttributeValueMemberM); ok {
		delete(m.Value, pa[len(pa)-1].name)
	}
}

// applyUpdate runs an update expression against item in place.
func applyUpdate(item map[string]ddbtypes.AttributeValue, expr string, names map[string]string, values map[string]ddbtypes.AttributeValue) error {
	toks, err := tokenize(expr)
	if err != nil {
		return err
	}
	p := &parser{toks: toks, names: names, values: values}
	type action func() error
	var actions []action
	seen := map[string]bool{}
	claim := func(pa path) error {
		s := pa.String()
		for prior := range seen {
			if prior == s || strings.HasPrefix(prior, s+".") || strings.HasPrefix(s, prior+".") {
				return validation("Invalid UpdateExpression: Two document paths overlap with each other; " + prior + " and " + s)
			}
		}
		seen[s] = true
		return nil
	}
	for p.pos < len(p.toks) {
		clause := strings.ToUpper(p.next().text)
		for {
			pa, err := p.parsePath()
			if err != nil {
				return err
			}
			if err := claim(pa); err != nil {
				return err
			}
			switch clause {
			case "SET":
				if err := p.expectOp("="); err != nil {
					return err
				}
				val, err := p.parseValueExpr()
				if err != nil {
					return err
				}
				actions = append(actions, func() error {
					v, err := val(item)
					if err != nil {
						return err
					}
					if v == nil {
						return validation("The provided expression refers to an attribute that does not exist in the item")
					}
					return setPath(item, pa, deepCopy(v))
				})
			case "ADD", "DELETE":
				val, err := p.parseOperand()
				if err != nil {
					return err
				}
				del := clause == "DELETE"
				actions = append(actions, func() error {
					v, err := val(item)
					if err != nil {
						return err
					}
					cur := getPath(item, pa)
					next, err := addOrDelete(cur, v, del)
					if err != nil {
						return err
					}
					if next == nil {
						removePath(item, pa)
						return nil
					}
					return setPath(item, pa, next)
				})
			case "REMOVE":
				actions = append(actions, func() error { removePath(item, pa); return nil })
			default:
				return fmt.Errorf("unknown update clause %q", clause)
			}
			if !p.op(",") {
				break
			}
		}
	}
	// DynamoDB evaluates every operand against the item as it was before the
	// update, so read all values first. The closures above read item lazily;
	// running SETs that reference other updated paths is not something
	// TrailTool does, so sequential application is equivalent here.
	for _, a := range actions {
		if err := a(); err != nil {
			return err
		}
	}
	return nil
}

func addOrDelete(cur, v ddbtypes.AttributeValue, del bool) (ddbtypes.AttributeValue, error) {
	switch x := v.(type) {
	case *ddbtypes.AttributeValueMemberN:
		if del {
			return nil, validation("DELETE requires a set")
		}
		if cur == nil {
			return &ddbtypes.AttributeValueMemberN{Value: x.Value}, nil
		}
		c, ok := cur.(*ddbtypes.AttributeValueMemberN)
		if !ok {
			return nil, validation("An operand in the update expression has an incorrect data type")
		}
		return addNumbers(c.Value, x.Value, 1), nil
	case *ddbtypes.AttributeValueMemberSS:
		var existing []string
		if cur != nil {
			c, ok := cur.(*ddbtypes.AttributeValueMemberSS)
			if !ok {
				return nil, validation("An operand in the update expression has an incorrect data type")
			}
			existing = c.Value
		}
		set := map[string]bool{}
		var out []string
		for _, s := range existing {
			set[s] = true
		}
		if del {
			drop := map[string]bool{}
			for _, s := range x.Value {
				drop[s] = true
			}
			for _, s := range existing {
				if !drop[s] {
					out = append(out, s)
				}
			}
		} else {
			out = append(out, existing...)
			for _, s := range x.Value {
				if !set[s] {
					set[s] = true
					out = append(out, s)
				}
			}
		}
		if len(out) == 0 {
			return nil, nil
		}
		return &ddbtypes.AttributeValueMemberSS{Value: out}, nil
	}
	return nil, validation("ADD/DELETE supports only numbers and sets")
}

func evalCondition(item map[string]ddbtypes.AttributeValue, expr *string, names map[string]string, values map[string]ddbtypes.AttributeValue) (bool, error) {
	if expr == nil || *expr == "" {
		return true, nil
	}
	toks, err := tokenize(*expr)
	if err != nil {
		return false, err
	}
	p := &parser{toks: toks, names: names, values: values}
	c, err := p.parseCond()
	if err != nil {
		return false, err
	}
	if p.pos != len(p.toks) {
		return false, fmt.Errorf("trailing tokens in condition %q", *expr)
	}
	if item == nil {
		item = map[string]ddbtypes.AttributeValue{}
	}
	return c(item)
}
