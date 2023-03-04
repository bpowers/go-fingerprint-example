package fingerprint

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"sync/atomic"
)

const demoFingerprint = "definitely a fingerprint"

type fingerprintKey struct{}

type fingerprint struct {
	hex atomic.Pointer[string]
}

// GetFingerprint returns the TLS fingerprint of this connection
func GetFingerprint(ctx context.Context) (fpHex string, ok bool) {
	if fp, ok := ctx.Value(fingerprintKey{}).(*fingerprint); ok {
		if hexp := fp.hex.Load(); hexp != nil {
			return *hexp, true
		}
	}

	return "", false
}

type conn struct {
	net.Conn
	fingerprint atomic.Pointer[fingerprint]
}

var _ net.Conn = &conn{}

type listener struct {
	inner net.Listener
}

func (l *listener) Accept() (net.Conn, error) {
	c, err := l.inner.Accept()
	if err != nil {
		return nil, err
	}
	return &conn{Conn: c}, nil
}

func (l *listener) Close() error {
	return l.inner.Close()
}

func (l *listener) Addr() net.Addr {
	return l.inner.Addr()
}

var _ net.Listener = &listener{}

type Server struct {
	*http.Server
	cert atomic.Pointer[tls.Certificate]
}

func (srv *Server) ListenAndServeTLS(certFile, keyFile string) error {
	addr := srv.Addr
	if addr == "" {
		addr = ":https"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	defer ln.Close()

	return srv.ServeTLS(ln, certFile, keyFile)
}

func buildFingerprint(ch *tls.ClientHelloInfo) string {
	// TODO
	return demoFingerprint
}

func (srv *Server) getCertificate(ch *tls.ClientHelloInfo) (*tls.Certificate, error) {
	fpHex := buildFingerprint(ch)

	conn := ch.Conn.(*conn)
	conn.fingerprint.Load().hex.Store(&fpHex)

	return srv.cert.Load(), nil
}

func fingerprintedContext(ctx context.Context, netConn net.Conn) context.Context {
	conn := netConn.(*tls.Conn).NetConn().(*conn)
	if conn.fingerprint.Load() == nil {
		conn.fingerprint.CompareAndSwap(nil, &fingerprint{})
	}

	return context.WithValue(ctx, fingerprintKey{}, conn.fingerprint.Load())
}

func (srv *Server) ServeTLS(l net.Listener, certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}
	srv.cert.Store(&cert)

	if srv.TLSConfig == nil {
		srv.TLSConfig = &tls.Config{
			GetCertificate: srv.getCertificate,
		}
	}

	srv.ConnContext = fingerprintedContext

	return srv.Server.ServeTLS(&listener{l}, "", "")
}
