package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// HTTPTimeout bounds one request. Two requests (the retry after a 401 or
	// 403) and a secret read fit well inside the 30-second Lambda timeout.
	HTTPTimeout = 10 * time.Second

	contentTypeProtobuf = "application/x-protobuf"
	maxResponseBytes    = 64 * 1024
	maxErrorMessage     = 256
)

// SecretReader is the subset of the Secrets Manager client the exporter uses.
// *secretsmanager.Client satisfies it.
type SecretReader interface {
	GetSecretValue(ctx context.Context, params *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// Exporter posts OTLP/HTTP protobuf log payloads to one endpoint, with headers
// read from a Secrets Manager secret holding a JSON object of header name to
// value.
type Exporter struct {
	endpoint string
	client   *http.Client
	secrets  SecretReader
	secretID string

	mu      sync.Mutex
	headers map[string]string
}

// NewExporter returns an exporter. client nil means a client with HTTPTimeout.
func NewExporter(endpoint string, client *http.Client, secrets SecretReader, secretID string) *Exporter {
	if client == nil {
		client = &http.Client{Timeout: HTTPTimeout}
	}
	return &Exporter{endpoint: endpoint, client: client, secrets: secrets, secretID: secretID}
}

// Result is what one export reports for logging. It never holds header values
// or the request body.
type Result struct {
	Status   int
	Rejected int64
}

// Export sends one payload. The headers secret is read on first use and
// cached; a 401 or 403 re-reads it once and retries, so a rotated credential
// takes effect without a redeploy. Any non-2xx status, or a partial success
// that rejected records, is an error.
func (e *Exporter) Export(ctx context.Context, body []byte) (Result, error) {
	headers, err := e.loadHeaders(ctx, false)
	if err != nil {
		return Result{}, err
	}
	res, err := e.post(ctx, body, headers)
	if res.Status == http.StatusUnauthorized || res.Status == http.StatusForbidden {
		if headers, err = e.loadHeaders(ctx, true); err != nil {
			return res, err
		}
		res, err = e.post(ctx, body, headers)
	}
	if err != nil {
		return res, e.redact(err)
	}
	return res, nil
}

func (e *Exporter) loadHeaders(ctx context.Context, reload bool) (map[string]string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.headers != nil && !reload {
		return e.headers, nil
	}
	out, err := e.secrets.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{SecretId: aws.String(e.secretID)})
	if err != nil {
		return nil, fmt.Errorf("read headers secret: %w", err)
	}
	headers, err := parseHeaders(aws.ToString(out.SecretString))
	if err != nil {
		return nil, err
	}
	e.headers = headers
	return headers, nil
}

// parseHeaders decodes the secret. Errors never quote the secret's content.
func parseHeaders(secret string) (map[string]string, error) {
	var headers map[string]string
	if err := json.Unmarshal([]byte(secret), &headers); err != nil {
		return nil, errors.New("headers secret must be a JSON object of header name to string value")
	}
	for name := range headers {
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("headers secret has an empty header name")
		}
	}
	if headers == nil {
		headers = map[string]string{}
	}
	return headers, nil
}

func (e *Exporter) post(ctx context.Context, body []byte, headers map[string]string) (Result, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint, bytes.NewReader(body))
	if err != nil {
		return Result{}, fmt.Errorf("build request: %w", err)
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	req.Header.Set("Content-Type", contentTypeProtobuf)

	resp, err := e.client.Do(req)
	if err != nil {
		return Result{}, fmt.Errorf("post logs: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

	res := Result{Status: resp.StatusCode}
	isProtobuf := mediaType(resp.Header.Get("Content-Type")) == contentTypeProtobuf
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return res, fmt.Errorf("otlp endpoint returned HTTP %d: %s", resp.StatusCode, errorMessage(respBody, isProtobuf))
	}
	rejected, message := partialSuccess(respBody, isProtobuf)
	res.Rejected = rejected
	if rejected > 0 {
		return res, fmt.Errorf("otlp endpoint rejected %d log records: %s", rejected, clip(message))
	}
	return res, nil
}

// minRedactBytes is the shortest header value, or word of one, that redact
// strips. Credentials are longer; shorter values such as "1" would mangle the
// message.
const minRedactBytes = 8

// redact strips header values from an error, in case a receiver echoes a
// credential back in its error message. Besides each whole value it strips
// each long word of it, so "Bearer <token>" also hides a bare token.
func (e *Exporter) redact(err error) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	msg := err.Error()
	redacted := msg
	for _, value := range e.headers {
		if len(value) >= minRedactBytes {
			redacted = strings.ReplaceAll(redacted, value, "[redacted]")
		}
		for word := range strings.FieldsSeq(value) {
			if len(word) >= minRedactBytes {
				redacted = strings.ReplaceAll(redacted, word, "[redacted]")
			}
		}
	}
	if redacted == msg {
		return err
	}
	return errors.New(redacted)
}

func mediaType(contentType string) string {
	mt, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return ""
	}
	return mt
}

// errorMessage extracts a failure response's message: google.rpc.Status
// field 2 for protobuf, the body text otherwise.
func errorMessage(body []byte, isProtobuf bool) string {
	if isProtobuf {
		if msg, _ := stringField(body, 2); msg != "" {
			return clip(msg)
		}
		return "(no status message)"
	}
	return clip(string(body))
}

// partialSuccess reads ExportLogsServiceResponse.partial_success: field 1,
// holding rejected_log_records (1) and error_message (2). A body that does
// not parse reports nothing rejected.
func partialSuccess(body []byte, isProtobuf bool) (int64, string) {
	if !isProtobuf {
		var resp struct {
			PartialSuccess struct {
				RejectedLogRecords json.Number `json:"rejectedLogRecords"`
				ErrorMessage       string      `json:"errorMessage"`
			} `json:"partialSuccess"`
		}
		if json.Unmarshal(body, &resp) != nil {
			return 0, ""
		}
		rejected, _ := strconv.ParseInt(resp.PartialSuccess.RejectedLogRecords.String(), 10, 64)
		return rejected, resp.PartialSuccess.ErrorMessage
	}
	ps, ok := bytesField(body, 1)
	if !ok {
		return 0, ""
	}
	rejected, _ := varintField(ps, 1)
	message, _ := stringField(ps, 2)
	return int64(rejected), message
}

// clip shortens a receiver message to one bounded line.
func clip(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	return truncateBytes(s, maxErrorMessage)
}

func bytesField(b []byte, num protowire.Number) ([]byte, bool) {
	var found []byte
	ok := walkFields(b, func(n protowire.Number, typ protowire.Type, v []byte) {
		if n == num && typ == protowire.BytesType {
			found = v
		}
	})
	return found, ok && found != nil
}

func stringField(b []byte, num protowire.Number) (string, bool) {
	v, ok := bytesField(b, num)
	return string(v), ok
}

func varintField(b []byte, num protowire.Number) (uint64, bool) {
	var found uint64
	seen := false
	ok := walkFields(b, func(n protowire.Number, typ protowire.Type, v []byte) {
		if n == num && typ == protowire.VarintType {
			found, _ = protowire.ConsumeVarint(v)
			seen = true
		}
	})
	return found, ok && seen
}

// walkFields calls fn for each top-level field of a protobuf message, with
// the field's raw value (length-delimited content, or the varint bytes).
// It reports false on malformed input.
func walkFields(b []byte, fn func(protowire.Number, protowire.Type, []byte)) bool {
	for len(b) > 0 {
		num, typ, n := protowire.ConsumeTag(b)
		if n < 0 {
			return false
		}
		b = b[n:]
		var value []byte
		switch typ {
		case protowire.BytesType:
			v, m := protowire.ConsumeBytes(b)
			if m < 0 {
				return false
			}
			value, n = v, m
		default:
			m := protowire.ConsumeFieldValue(num, typ, b)
			if m < 0 {
				return false
			}
			value, n = b[:m], m
		}
		fn(num, typ, value)
		b = b[n:]
	}
	return true
}
