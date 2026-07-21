package models

import "testing"

// The sid algorithm is duplicated in ingestor/lib/identity.Sid (write side) and
// SidForRef here (read side) because the two module trees don't import each
// other. These golden values pin the algorithm so the copies can't silently
// drift — a divergence would make the CLI compute a different sid than the
// ingestor stored, breaking --session lookups and drilldown hints. If you change
// the algorithm, update identity.Sid to match and re-pin both.
func TestSidForRefGolden(t *testing.T) {
	cases := map[string]string{
		"email#alice@example.com|win#arn:aws:iam::123456789012:role/Admin#2026-04-15T17:08:23Z": "wi753omd65ue3fcn",
		"a": "zklycewkdo64v6wc",
		"b": "hyr6qfqahfmuum4j",
	}
	for ref, want := range cases {
		if got := SidForRef(ref); got != want {
			t.Errorf("SidForRef(%q) = %q, want %q", ref, got, want)
		}
	}
}

func TestSidForRefProperties(t *testing.T) {
	sid := SidForRef("email#alice@example.com|sis#session-1")
	if len(sid) != sidLength {
		t.Errorf("sid length = %d, want %d", len(sid), sidLength)
	}
	// Deterministic.
	if again := SidForRef("email#alice@example.com|sis#session-1"); again != sid {
		t.Errorf("SidForRef not deterministic: %q != %q", sid, again)
	}
	// Session.SidForRef mirrors the package function.
	s := &Session{PersonKey: "email#alice@example.com", SK: "sis#session-1"}
	if s.SidForRef() != sid {
		t.Errorf("Session.SidForRef() = %q, want %q", s.SidForRef(), sid)
	}
}
