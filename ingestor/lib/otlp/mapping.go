// Package otlp turns TrailTool change events, as EventBridge delivers them,
// into OpenTelemetry log records and sends them to an OTLP/HTTP logs endpoint.
// Field mapping and delivery semantics: docs/design/otlp-forwarder.md.
package otlp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	lambdaevents "github.com/aws/aws-lambda-go/events"
	commonv1 "go.opentelemetry.io/proto/otlp/common/v1"
	logsv1 "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcev1 "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/proto"

	"github.com/engseclabs/trailtool/ingestor/lib/events"
)

const (
	// ScopeName is the instrumentation scope of every record.
	ScopeName = "trailtool"
	// AttributePrefix namespaces the flattened detail fields.
	AttributePrefix = "trailtool."

	// MaxArrayItems caps every array value; the rest are counted in a
	// sibling <key>_dropped attribute.
	MaxArrayItems = 25
	// MaxMapEntries caps each map-valued field (mapFields), keeping the first
	// keys in sorted order; the rest are counted in <key>_dropped.
	MaxMapEntries = 100
	// MaxStringBytes caps every string value.
	MaxStringBytes = 2048
	// MaxRecordBytes is the encoded size a record is trimmed to, by dropping
	// trailing items from its largest arrays. Receivers commonly cap a record
	// at 256 KB or more; this stays well under.
	MaxRecordBytes = 64 * 1024

	severityInfo = logsv1.SeverityNumber_SEVERITY_NUMBER_INFO
	severityWarn = logsv1.SeverityNumber_SEVERITY_NUMBER_WARN
)

// mapFields are detail objects whose keys are data (event names, tag keys,
// request parameter names) rather than schema. Flattening them would mint an
// attribute name per value, so they stay one map-valued attribute.
var mapFields = map[string]bool{
	"event_counts":        true,
	"denied_event_counts": true,
	"session_tags":        true,
	"subject_counts":      true,
	"request_parameters":  true,
}

// Resource describes the forwarder's own identity on every record.
type Resource struct {
	ServiceName  string
	ScopeVersion string
}

// BuildLogs maps one EventBridge event to an OTLP logs payload holding a
// single record. now is the observed time.
//
// LogsData is wire-identical to ExportLogsServiceRequest, so its encoding is
// the OTLP/HTTP request body without importing the gRPC service package.
func BuildLogs(ev lambdaevents.EventBridgeEvent, res Resource, now time.Time) *logsv1.LogsData {
	return &logsv1.LogsData{
		ResourceLogs: []*logsv1.ResourceLogs{{
			Resource: &resourcev1.Resource{Attributes: resourceAttributes(ev, res)},
			ScopeLogs: []*logsv1.ScopeLogs{{
				Scope:      &commonv1.InstrumentationScope{Name: ScopeName, Version: res.ScopeVersion},
				LogRecords: []*logsv1.LogRecord{BuildRecord(ev, now)},
			}},
		}},
	}
}

// BuildRecord maps one EventBridge event to a log record.
func BuildRecord(ev lambdaevents.EventBridgeEvent, now time.Time) *logsv1.LogRecord {
	body, severity := summarize(ev.DetailType, ev.Detail)
	record := &logsv1.LogRecord{
		ObservedTimeUnixNano: uint64(now.UnixNano()),
		SeverityNumber:       severity,
		SeverityText:         severityText(severity),
		Body:                 stringValue(body),
		EventName:            ev.DetailType,
	}
	if !ev.Time.IsZero() {
		record.TimeUnixNano = uint64(ev.Time.UnixNano())
	}

	attrs := []*commonv1.KeyValue{
		{Key: "event.name", Value: stringValue(ev.DetailType)},
		{Key: AttributePrefix + "event_id", Value: stringValue(ev.ID)},
	}
	dropped := make(map[string]int)
	if detail, err := decodeObject(ev.Detail); err == nil {
		attrs = flatten(strings.TrimSuffix(AttributePrefix, "."), detail, attrs, dropped)
	}
	record.Attributes = attrs
	fitRecord(record, dropped)
	record.Attributes = append(record.Attributes, droppedAttributes(dropped)...)
	return record
}

func resourceAttributes(ev lambdaevents.EventBridgeEvent, res Resource) []*commonv1.KeyValue {
	attrs := []*commonv1.KeyValue{
		{Key: "service.name", Value: stringValue(res.ServiceName)},
		{Key: "cloud.provider", Value: stringValue("aws")},
	}
	if ev.AccountID != "" {
		attrs = append(attrs, &commonv1.KeyValue{Key: "cloud.account.id", Value: stringValue(ev.AccountID)})
	}
	if ev.Region != "" {
		attrs = append(attrs, &commonv1.KeyValue{Key: "cloud.region", Value: stringValue(ev.Region)})
	}
	return attrs
}

// summarize builds the human-readable body and picks the severity. Session
// Activity with any denied call is WARN; everything else is INFO.
func summarize(detailType string, raw json.RawMessage) (string, logsv1.SeverityNumber) {
	switch detailType {
	case events.DetailTypeNounCreated:
		var d events.NounCreated
		if json.Unmarshal(raw, &d) == nil {
			return fmt.Sprintf("%s %s seen for the first time", d.Kind, nounLabel(d.Noun)), severityInfo
		}
	case events.DetailTypeRelationCreated:
		var d events.RelationCreated
		if json.Unmarshal(raw, &d) == nil {
			return fmt.Sprintf("%s %s reached %s %s for the first time",
				d.Subject.Kind, nounLabel(d.Subject), d.Related.Kind, nounLabel(d.Related)), severityInfo
		}
	case events.DetailTypeSessionActivity:
		var d events.SessionActivity
		if json.Unmarshal(raw, &d) == nil {
			return sessionSummary(d), sessionSeverity(d)
		}
	}
	return detailType, severityInfo
}

func nounLabel(n events.Noun) string {
	if n.Identifier != "" && n.AccountID != "" {
		return n.Identifier + " in account " + n.AccountID
	}
	return n.ID
}

func sessionSummary(d events.SessionActivity) string {
	who := firstNonEmpty(d.Session.Person.Email, d.Session.Person.Label, d.Session.Person.Key, d.Session.RoleARN, d.Session.Sid)
	session := d.Session.Type + " session"
	if d.Session.NewSession {
		session = "new " + session
	}
	return fmt.Sprintf("%s: %d calls, %d denied, %d writes in account %s (%s %s)",
		who, d.Activity.EventsCount, d.Activity.DeniedCount, d.Activity.WriteCount,
		d.Session.AccountID, session, d.Session.Sid)
}

func sessionSeverity(d events.SessionActivity) logsv1.SeverityNumber {
	if d.Activity.DeniedCount > 0 {
		return severityWarn
	}
	return severityInfo
}

func severityText(s logsv1.SeverityNumber) string {
	if s == severityWarn {
		return "WARN"
	}
	return "INFO"
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

// decodeObject decodes a detail, keeping numbers exact so counts stay ints.
func decodeObject(raw json.RawMessage) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var obj map[string]any
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// flatten appends obj's fields under prefix as dotted keys. Nested objects
// flatten further unless they are mapFields; arrays and map fields become
// array and kvlist values. Keys are sorted so output is deterministic.
func flatten(prefix string, obj map[string]any, out []*commonv1.KeyValue, dropped map[string]int) []*commonv1.KeyValue {
	for _, k := range sortedKeys(obj) {
		key := prefix + "." + k
		switch v := obj[k].(type) {
		case nil:
		case map[string]any:
			if mapFields[k] {
				out = append(out, &commonv1.KeyValue{Key: key, Value: anyValue(capMap(key, v, dropped))})
			} else {
				out = flatten(key, v, out, dropped)
			}
		case []any:
			if len(v) > MaxArrayItems {
				dropped[key] += len(v) - MaxArrayItems
				v = v[:MaxArrayItems]
			}
			out = append(out, &commonv1.KeyValue{Key: key, Value: anyValue(v)})
		default:
			out = append(out, &commonv1.KeyValue{Key: key, Value: anyValue(v)})
		}
	}
	return out
}

// capMap keeps the first MaxMapEntries keys of m in sorted order.
func capMap(key string, m map[string]any, dropped map[string]int) map[string]any {
	if len(m) <= MaxMapEntries {
		return m
	}
	kept := make(map[string]any, MaxMapEntries)
	for _, k := range sortedKeys(m)[:MaxMapEntries] {
		kept[k] = m[k]
	}
	dropped[key] += len(m) - MaxMapEntries
	return kept
}

// anyValue converts a decoded JSON value. Arrays nested inside values are
// capped too, without a dropped count.
func anyValue(v any) *commonv1.AnyValue {
	switch v := v.(type) {
	case string:
		return stringValue(v)
	case bool:
		return &commonv1.AnyValue{Value: &commonv1.AnyValue_BoolValue{BoolValue: v}}
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: i}}
		}
		f, _ := v.Float64()
		return &commonv1.AnyValue{Value: &commonv1.AnyValue_DoubleValue{DoubleValue: f}}
	case []any:
		if len(v) > MaxArrayItems {
			v = v[:MaxArrayItems]
		}
		values := make([]*commonv1.AnyValue, 0, len(v))
		for _, item := range v {
			values = append(values, anyValue(item))
		}
		return &commonv1.AnyValue{Value: &commonv1.AnyValue_ArrayValue{ArrayValue: &commonv1.ArrayValue{Values: values}}}
	case map[string]any:
		kvs := make([]*commonv1.KeyValue, 0, len(v))
		for _, k := range sortedKeys(v) {
			if v[k] != nil {
				kvs = append(kvs, &commonv1.KeyValue{Key: k, Value: anyValue(v[k])})
			}
		}
		return &commonv1.AnyValue{Value: &commonv1.AnyValue_KvlistValue{KvlistValue: &commonv1.KeyValueList{Values: kvs}}}
	}
	return &commonv1.AnyValue{}
}

func stringValue(s string) *commonv1.AnyValue {
	return &commonv1.AnyValue{Value: &commonv1.AnyValue_StringValue{StringValue: truncateBytes(s, MaxStringBytes)}}
}

// truncateBytes cuts s to at most n bytes without splitting a rune.
func truncateBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// fitRecord drops trailing items from the record's largest top-level array
// until the record fits MaxRecordBytes, counting them in dropped. It reserves
// room for the dropped-count attributes added afterwards.
func fitRecord(record *logsv1.LogRecord, dropped map[string]int) {
	const reserve = 512
	for proto.Size(record) > MaxRecordBytes-reserve {
		var largest *commonv1.KeyValue
		largestSize := 0
		for _, kv := range record.Attributes {
			arr := kv.Value.GetArrayValue()
			if arr == nil || len(arr.Values) == 0 {
				continue
			}
			if size := proto.Size(arr); size > largestSize {
				largest, largestSize = kv, size
			}
		}
		if largest == nil {
			return
		}
		arr := largest.Value.GetArrayValue()
		arr.Values = arr.Values[:len(arr.Values)-1]
		dropped[largest.Key]++
	}
}

func droppedAttributes(dropped map[string]int) []*commonv1.KeyValue {
	keys := make([]string, 0, len(dropped))
	for k := range dropped {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	attrs := make([]*commonv1.KeyValue, 0, len(keys))
	for _, k := range keys {
		attrs = append(attrs, &commonv1.KeyValue{
			Key:   k + "_dropped",
			Value: &commonv1.AnyValue{Value: &commonv1.AnyValue_IntValue{IntValue: int64(dropped[k])}},
		})
	}
	return attrs
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
