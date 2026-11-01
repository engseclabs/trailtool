package otlp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"google.golang.org/protobuf/encoding/protowire"

	"github.com/engseclabs/trailtool/ingestor/lib/events"
)

const (
	testToken  = "s3cr3t-token-value"
	testTenant = "tenant-7f3a9c"
)

// fakeSecrets returns the secret values in order, repeating the last.
type fakeSecrets struct {
	values []string
	calls  atomic.Int32
	err    error
}

func (f *fakeSecrets) GetSecretValue(_ context.Context, in *secretsmanager.GetSecretValueInput, _ ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	n := int(f.calls.Add(1)) - 1
	if f.err != nil {
		return nil, f.err
	}
	if n >= len(f.values) {
		n = len(f.values) - 1
	}
	return &secretsmanager.GetSecretValueOutput{SecretString: aws.String(f.values[n])}, nil
}

func headerSecret(token string) string {
	return `{"Authorization":"Bearer ` + token + `","X-Tenant":"` + testTenant + `"}`
}

// partialSuccessBody encodes ExportLogsServiceResponse{partial_success:
// {rejected_log_records, error_message}}.
func partialSuccessBody(rejected int64, message string) []byte {
	var ps []byte
	ps = protowire.AppendTag(ps, 1, protowire.VarintType)
	ps = protowire.AppendVarint(ps, uint64(rejected))
	ps = protowire.AppendTag(ps, 2, protowire.BytesType)
	ps = protowire.AppendString(ps, message)
	var resp []byte
	resp = protowire.AppendTag(resp, 1, protowire.BytesType)
	return protowire.AppendBytes(resp, ps)
}

// statusBody encodes google.rpc.Status{code, message}.
func statusBody(code int, message string) []byte {
	var b []byte
	b = protowire.AppendTag(b, 1, protowire.VarintType)
	b = protowire.AppendVarint(b, uint64(code))
	b = protowire.AppendTag(b, 2, protowire.BytesType)
	return protowire.AppendString(b, message)
}

func protobufResponse(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Content-Type", "application/x-protobuf")
	w.WriteHeader(status)
	w.Write(body)
}

func TestExportSuccess(t *testing.T) {
	var gotAuth, gotTenant, gotType string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotTenant, gotType = r.Header.Get("Authorization"), r.Header.Get("X-Tenant"), r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		protobufResponse(w, http.StatusOK, nil)
	}))
	defer srv.Close()

	secrets := &fakeSecrets{values: []string{headerSecret(testToken)}}
	exp := NewExporter(srv.URL, nil, secrets, "arn:secret")
	for range 2 {
		res, err := exp.Export(context.Background(), []byte("payload"))
		if err != nil {
			t.Fatalf("Export: %v", err)
		}
		if res.Status != http.StatusOK || res.Rejected != 0 {
			t.Errorf("result = %+v", res)
		}
	}
	if gotAuth != "Bearer "+testToken || gotTenant != testTenant {
		t.Errorf("headers = %q, %q", gotAuth, gotTenant)
	}
	if gotType != "application/x-protobuf" {
		t.Errorf("Content-Type = %q", gotType)
	}
	if string(gotBody) != "payload" {
		t.Errorf("body = %q", gotBody)
	}
	if n := secrets.calls.Load(); n != 1 {
		t.Errorf("secret read %d times, want 1 (cached)", n)
	}
}

func TestExportEmptyPartialSuccessIsOK(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		protobufResponse(w, http.StatusOK, partialSuccessBody(0, ""))
	}))
	defer srv.Close()
	exp := NewExporter(srv.URL, nil, &fakeSecrets{values: []string{"{}"}}, "arn:secret")
	if _, err := exp.Export(context.Background(), nil); err != nil {
		t.Fatalf("Export: %v", err)
	}
}

func TestExportErrorStatuses(t *testing.T) {
	for _, status := range []int{http.StatusBadRequest, http.StatusTooManyRequests, http.StatusInternalServerError, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				protobufResponse(w, status, statusBody(3, "bad things"))
			}))
			defer srv.Close()
			exp := NewExporter(srv.URL, nil, &fakeSecrets{values: []string{headerSecret(testToken)}}, "arn:secret")
			res, err := exp.Export(context.Background(), nil)
			if err == nil {
				t.Fatal("Export succeeded, want an error")
			}
			if res.Status != status {
				t.Errorf("status = %d, want %d", res.Status, status)
			}
			if !strings.Contains(err.Error(), "bad things") {
				t.Errorf("error %q lacks the receiver's status message", err)
			}
		})
	}
}

func TestExportTextErrorBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream\n\tunavailable", http.StatusBadGateway)
	}))
	defer srv.Close()
	exp := NewExporter(srv.URL, nil, &fakeSecrets{values: []string{"{}"}}, "arn:secret")
	_, err := exp.Export(context.Background(), nil)
	if err == nil || !strings.Contains(err.Error(), "HTTP 502: upstream unavailable") {
		t.Errorf("error = %v, want HTTP 502 with the body on one line", err)
	}
}

func TestRedactSkipsShortValues(t *testing.T) {
	exp := NewExporter("http://unused", nil, nil, "")
	exp.headers = map[string]string{"X-Debug": "1", "Authorization": "Bearer " + testToken}
	got := exp.redact(errors.New("HTTP 401: bad token " + testToken)).Error()
	if want := "HTTP 401: bad token [redacted]"; got != want {
		t.Errorf("redact = %q, want %q", got, want)
	}
}

func TestExportPartialSuccessIsError(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"protobuf": func(w http.ResponseWriter, r *http.Request) {
			protobufResponse(w, http.StatusOK, partialSuccessBody(1, "record too large"))
		},
		"json": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			io.WriteString(w, `{"partialSuccess":{"rejectedLogRecords":"1","errorMessage":"record too large"}}`)
		},
	} {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(handler)
			defer srv.Close()
			exp := NewExporter(srv.URL, nil, &fakeSecrets{values: []string{"{}"}}, "arn:secret")
			res, err := exp.Export(context.Background(), nil)
			if err == nil {
				t.Fatal("Export succeeded, want an error")
			}
			if res.Rejected != 1 || !strings.Contains(err.Error(), "record too large") {
				t.Errorf("result = %+v, err = %v", res, err)
			}
		})
	}
}

func TestExportAuthFailureRereadsSecretOnce(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			// The endpoint accepts only the rotated token.
			var requests atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				if r.Header.Get("Authorization") != "Bearer rotated" {
					w.WriteHeader(status)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			secrets := &fakeSecrets{values: []string{headerSecret("stale"), headerSecret("rotated")}}
			exp := NewExporter(srv.URL, nil, secrets, "arn:secret")
			if _, err := exp.Export(context.Background(), nil); err != nil {
				t.Fatalf("Export: %v", err)
			}
			if n := secrets.calls.Load(); n != 2 {
				t.Errorf("secret read %d times, want 2 (initial and one re-read)", n)
			}
			if n := requests.Load(); n != 2 {
				t.Errorf("%d requests, want 2", n)
			}
			// The rotated value stays cached.
			if _, err := exp.Export(context.Background(), nil); err != nil {
				t.Fatalf("second Export: %v", err)
			}
			if n := secrets.calls.Load(); n != 2 {
				t.Errorf("secret read %d times after a good export, want 2", n)
			}
		})
	}
}

func TestExportPersistentAuthFailureRereadsOnlyOnce(t *testing.T) {
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	secrets := &fakeSecrets{values: []string{headerSecret(testToken)}}
	exp := NewExporter(srv.URL, nil, secrets, "arn:secret")
	res, err := exp.Export(context.Background(), nil)
	if err == nil || res.Status != http.StatusUnauthorized {
		t.Fatalf("result = %+v, err = %v; want a 401 error", res, err)
	}
	if n := secrets.calls.Load(); n != 2 {
		t.Errorf("secret read %d times, want exactly 2", n)
	}
	if n := requests.Load(); n != 2 {
		t.Errorf("%d requests, want 2", n)
	}
}

func TestExportSecretErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request sent without headers")
	}))
	defer srv.Close()
	for name, secrets := range map[string]*fakeSecrets{
		"read fails": {err: errors.New("AccessDeniedException")},
		"not json":   {values: []string{"Bearer " + testToken}},
		"non-string": {values: []string{`{"Authorization": 1}`}},
		"empty name": {values: []string{`{" ": "` + testToken + `"}`}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := NewExporter(srv.URL, nil, secrets, "arn:secret").Export(context.Background(), nil)
			if err == nil {
				t.Fatal("Export succeeded, want an error")
			}
			if strings.Contains(err.Error(), testToken) {
				t.Errorf("error leaks the secret: %v", err)
			}
		})
	}
}

// TestForwarderNeverLogsSecrets runs every outcome through the handler and
// checks that neither the log output nor the returned error carries a header
// value or the request body, even when the receiver echoes them back.
func TestForwarderNeverLogsSecrets(t *testing.T) {
	var buf bytes.Buffer
	original := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(original) })

	ev := envelopeEvent(t, events.DetailTypeSessionActivity, sessionActivity(1, 1))
	handlers := map[string]http.HandlerFunc{
		"ok": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) },
		"echo auth in 401": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "invalid key "+r.Header.Get("Authorization")+" for "+r.Header.Get("X-Tenant"), http.StatusUnauthorized)
		},
		"echo bare token in 403": func(w http.ResponseWriter, r *http.Request) {
			token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			http.Error(w, "token "+token+" lacks scope", http.StatusForbidden)
		},
		"echo in partial success": func(w http.ResponseWriter, r *http.Request) {
			protobufResponse(w, http.StatusOK, partialSuccessBody(1, "rejected for "+r.Header.Get("X-Tenant")))
		},
		"500": func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		},
	}
	for name, handler := range handlers {
		t.Run(name, func(t *testing.T) {
			buf.Reset()
			srv := httptest.NewServer(handler)
			defer srv.Close()
			f := &Forwarder{
				Exporter: NewExporter(srv.URL, nil, &fakeSecrets{values: []string{headerSecret(testToken)}}, "arn:secret"),
				Resource: Resource{ServiceName: "trailtool", ScopeVersion: "test"},
			}
			err := f.Handle(context.Background(), ev)

			out := buf.String()
			if err != nil {
				out += err.Error()
			}
			for _, secret := range []string{testToken, testTenant, "alice@example.com", "203.0.113.7"} {
				if strings.Contains(out, secret) {
					t.Errorf("output contains %q:\n%s", secret, out)
				}
			}
			if !strings.Contains(buf.String(), "id=eb-id-1") || !strings.Contains(buf.String(), `detail_type="TrailTool Session Activity"`) {
				t.Errorf("log lacks event id or detail-type:\n%s", buf.String())
			}
			if !strings.Contains(buf.String(), "status=") || !strings.Contains(buf.String(), "rejected=") {
				t.Errorf("log lacks status or rejected count:\n%s", buf.String())
			}
		})
	}
}
