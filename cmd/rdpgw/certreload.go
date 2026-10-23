package main

import (
	"crypto/tls"
	"log"
	"os"
	"sync"
	"time"
)

// certRecheck is how often the certificate files are looked at; between looks the loaded certificate is served as is.
const certRecheck = 30 * time.Second

// certReloader serves the certificate from CertFile / KeyFile and loads it again when either file changes, so a
// renewed certificate (a Kubernetes Secret volume, lego, certbot) is picked up without restarting the gateway.
// A file pair that no longer loads keeps the certificate that works until the pair loads again.
type certReloader struct {
	certFile, keyFile string

	mu      sync.Mutex
	cert    *tls.Certificate
	loaded  time.Time // newest modification time of the two files at the last successful load
	checked time.Time
}

func newCertReloader(certFile, keyFile string) (*certReloader, error) {
	r := &certReloader{certFile: certFile, keyFile: keyFile}
	if err := r.load(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *certReloader) modTime() (time.Time, error) {
	var newest time.Time
	for _, name := range []string{r.certFile, r.keyFile} {
		fi, err := os.Stat(name)
		if err != nil {
			return time.Time{}, err
		}
		if fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return newest, nil
}

// load reads the pair and keeps it only if it is a valid certificate and key. The caller holds mu (or owns r).
func (r *certReloader) load() error {
	mod, err := r.modTime()
	if err != nil {
		return err
	}
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return err
	}
	r.cert, r.loaded, r.checked = &cert, mod, time.Now()
	return nil
}

func (r *certReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if time.Since(r.checked) >= certRecheck {
		r.checked = time.Now()
		if mod, err := r.modTime(); err != nil {
			log.Printf("Cannot check certificate files, keeping the loaded certificate: %s", err)
		} else if mod != r.loaded {
			if err := r.load(); err != nil {
				log.Printf("Certificate files changed but do not load (%s), keeping the loaded certificate", err)
			} else {
				log.Printf("Certificate reloaded from %s", r.certFile)
			}
		}
	}
	return r.cert, nil
}
