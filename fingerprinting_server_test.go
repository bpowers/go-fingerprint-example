package fingerprint

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
)

func TestServer(t *testing.T) {
	invoked := new(atomic.Bool)

	testHandler := func(rw http.ResponseWriter, req *http.Request) {
		invoked.Store(true)
		fp, ok := GetFingerprint(req.Context())
		if !ok {
			t.Errorf("expected to find fingerprint in context")
		}
		if fp != demoFingerprint {
			t.Errorf("expected fp to be %q not %q", demoFingerprint, fp)
		}

		log.Printf("serving request on connection with fingerprint %q", fp)
		rw.WriteHeader(http.StatusOK)
	}

	srv := &Server{
		Server: &http.Server{
			Handler: http.HandlerFunc(testHandler),
		},
	}

	ln, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		if err := srv.ServeTLS(ln, "testdata/cert.pem", "testdata/key.pem"); err != nil {
			log.Printf("server closed with %s", err)
		}
	}()
	defer srv.Close()

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}

	resp, err := client.Get(fmt.Sprintf("https://%s/", ln.Addr().String()))
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200 status, not %d", resp.StatusCode)
	}

	if !invoked.Load() {
		t.Errorf("expected HTTP handler to be invoked")
	}
}
