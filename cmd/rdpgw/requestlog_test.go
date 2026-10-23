package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogRequestsNeverLogsTheCredential(t *testing.T) {
	var out bytes.Buffer
	log.SetOutput(&out)
	defer log.SetOutput(nil)

	h := logRequests(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	req := httptest.NewRequest("RDG_OUT_DATA", "/remoteDesktopGateway/", nil)
	req.Header.Set("Authorization", "Negotiate TOPSECRETTOKEN")
	req.Header.Set("User-Agent", "MSRPC")
	h.ServeHTTP(httptest.NewRecorder(), req)

	got := out.String()
	if strings.Contains(got, "TOPSECRETTOKEN") {
		t.Fatalf("the credential is in the log:\n%s", got)
	}
	for _, want := range []string{"Request RDG_OUT_DATA /remoteDesktopGateway/", `ua="MSRPC"`, "auth=Negotiate(14)", "-> 401"} {
		if !strings.Contains(got, want) {
			t.Fatalf("log lacks %q:\n%s", want, got)
		}
	}
}

func TestLogRequestsWithoutAuthorization(t *testing.T) {
	if got := authSummary(""); got != "none" {
		t.Fatalf("got %q, want none", got)
	}
	if got := authSummary("NTLM"); got != "NTLM(0)" {
		t.Fatalf("got %q, want NTLM(0)", got)
	}
}

func TestStatusRecorderKeepsFlushAndRefusesHijackOnPlainWriter(t *testing.T) {
	rec := &statusRecorder{ResponseWriter: httptest.NewRecorder()}
	rec.Flush()
	if _, _, err := rec.Hijack(); err == nil {
		t.Fatal("a recorder over a plain writer cannot hijack")
	}
}
