package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writePair writes a self-signed certificate for cn and its key, and gives both files the modification time mod.
func writePair(t *testing.T, dir, cn string, mod time.Time) (certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{certFile, keyFile} {
		if err := os.Chtimes(name, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	return certFile, keyFile
}

func commonName(t *testing.T, r *certReloader) string {
	t.Helper()
	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	return leaf.Subject.CommonName
}

func TestCertReloaderPicksUpRenewedCertificate(t *testing.T) {
	dir := t.TempDir()
	start := time.Now().Add(-time.Hour)
	certFile, keyFile := writePair(t, dir, "old", start)
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if got := commonName(t, r); got != "old" {
		t.Fatalf("got %q, want old", got)
	}

	writePair(t, dir, "new", start.Add(time.Minute))
	if got := commonName(t, r); got != "old" {
		t.Fatalf("files are only looked at every %s, got %q", certRecheck, got)
	}
	r.checked = time.Now().Add(-2 * certRecheck)
	if got := commonName(t, r); got != "new" {
		t.Fatalf("got %q after the files changed, want new", got)
	}
}

func TestCertReloaderKeepsWorkingCertificateWhenFilesBreak(t *testing.T) {
	dir := t.TempDir()
	start := time.Now().Add(-time.Hour)
	certFile, keyFile := writePair(t, dir, "good", start)
	r, err := newCertReloader(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	// a half written renewal: new modification time, certificate that is not one
	if err := os.WriteFile(certFile, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.checked = time.Now().Add(-2 * certRecheck)
	if got := commonName(t, r); got != "good" {
		t.Fatalf("got %q, want the loaded certificate to stay", got)
	}

	// the next renewal that loads replaces it
	writePair(t, dir, "renewed", start.Add(time.Hour))
	r.checked = time.Now().Add(-2 * certRecheck)
	if got := commonName(t, r); got != "renewed" {
		t.Fatalf("got %q, want renewed", got)
	}
}

func TestNewCertReloaderRejectsMissingFiles(t *testing.T) {
	if _, err := newCertReloader("/nonexistent/tls.crt", "/nonexistent/tls.key"); err == nil {
		t.Fatal("want an error for missing files")
	}
}
