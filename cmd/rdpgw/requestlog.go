package main

import (
	"bufio"
	"errors"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// logRequests logs every request and its outcome: method, path, protocol, user agent, the names of all headers the client
// sent (not their values) and, of Authorization, only the scheme and the length of the rest, never the credential.
// It is for finding out what a new gateway client sends, and is off unless RDPGW_LOG_REQUESTS is set.
func logRequests(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		names := make([]string, 0, len(r.Header))
		for name := range r.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		log.Printf("Request %s %s %s from %s ua=%q auth=%s upgrade=%q connection=%q length=%d headers=%s",
			r.Method, r.URL.Path, r.Proto, r.RemoteAddr, r.UserAgent(), authSummary(r.Header.Get("Authorization")),
			r.Header.Get("Upgrade"), r.Header.Get("Connection"), r.ContentLength, strings.Join(names, ","))

		rec := &statusRecorder{ResponseWriter: w}
		start := time.Now()
		h.ServeHTTP(rec, r)
		log.Printf("Response %s %s -> %d after %s", r.Method, r.URL.Path, rec.status, time.Since(start).Round(time.Millisecond))
	})
}

func authSummary(header string) string {
	if header == "" {
		return "none"
	}
	scheme, rest, _ := strings.Cut(header, " ")
	return scheme + "(" + strconv.Itoa(len(rest)) + ")"
}

// statusRecorder remembers the status code and keeps what the gateway needs from the writer: streaming and the
// connection takeover of the websocket transport.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if s.status == 0 {
		s.status = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (s *statusRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := s.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("response writer cannot hijack")
	}
	if s.status == 0 {
		s.status = http.StatusSwitchingProtocols
	}
	return h.Hijack()
}

func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }
