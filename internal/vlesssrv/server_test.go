// SPDX-License-Identifier: MPL-2.0

package vlesssrv

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/Chistovik92/zeropentime/internal/vless"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

// site is the "real website" REALITY imitates: a local TLS 1.3 server with
// a certificate for example.com.
func site(t *testing.T) *httptest.Server {
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("real site")) }))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func freeTCP(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().String()
}

type testServer struct {
	addr   string
	pub    [32]byte
	short  [8]byte
	user   vless.UUID
	dest   *httptest.Server
	cancel context.CancelFunc
}

// echoServer runs VLESS+REALITY that echoes every UDP packet back.
func echoServer(t *testing.T) *testServer {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ts := &testServer{addr: freeTCP(t), dest: site(t)}
	copy(ts.pub[:], key.PublicKey().Bytes())
	rand.Read(ts.short[:])
	rand.Read(ts.user[:])
	var priv [32]byte
	copy(priv[:], key.Bytes())
	ctx, cancel := context.WithCancel(context.Background())
	ts.cancel = cancel
	t.Cleanup(cancel)
	go Serve(ctx, ServerConfig{
		Listen: ts.addr, Dest: ts.dest.Listener.Addr().String(), ServerNames: []string{"example.com"},
		PrivateKey: priv, ShortID: ts.short,
		Allowed: func(u vless.UUID) bool { return u == ts.user },
		OnUDP: func(p *vless.PacketConn, _ netip.AddrPort, _ net.Addr) {
			defer p.Close()
			buf := make([]byte, vless.MaxPacket)
			for {
				n, err := p.ReadPacket(buf)
				if err != nil {
					return
				}
				p.WritePacket(buf[:n])
			}
		},
	}, quiet)
	return ts
}

func (ts *testServer) client() vless.ClientConfig {
	return vless.ClientConfig{Addr: ts.addr, ServerName: "example.com", PublicKey: ts.pub, ShortID: ts.short, User: ts.user}
}

func dial(t *testing.T, c vless.ClientConfig) (*vless.PacketConn, error) {
	var err error
	for range 50 { // the listener may not be up yet
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var p *vless.PacketConn
		p, err = vless.Dial(ctx, c, netip.MustParseAddrPort("127.0.0.1:3480"))
		cancel()
		if err == nil {
			return p, nil
		}
		var ne *net.OpError
		if !asOpErr(err, &ne) {
			return nil, err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil, err
}

func asOpErr(err error, target **net.OpError) bool {
	for err != nil {
		if e, ok := err.(*net.OpError); ok {
			*target = e
			return true
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

func TestRealityVLESSEcho(t *testing.T) {
	ts := echoServer(t)
	p, err := dial(t, ts.client())
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	buf := make([]byte, vless.MaxPacket)
	for _, msg := range [][]byte{[]byte("hello"), bytes.Repeat([]byte{7}, 1400), {}} {
		if err := p.WritePacket(msg); err != nil {
			t.Fatal(err)
		}
		n, err := p.ReadPacket(buf)
		if err != nil || !bytes.Equal(buf[:n], msg) {
			t.Fatalf("echo: %v, got %d bytes", err, n)
		}
	}
}

// Someone without our key (a censor's probe, or a wrong config) must get
// the real website — and our client must refuse it.
func TestWrongKeyGetsRealSite(t *testing.T) {
	ts := echoServer(t)
	c := ts.client()
	c.PublicKey[0] ^= 1
	if _, err := dial(t, c); err == nil {
		t.Fatal("connected with a wrong REALITY key")
	}
	// A plain HTTPS client sees the imitated site.
	var err error
	var body []byte
	for range 50 {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{ServerName: "example.com", RootCAs: rootsOf(ts.dest)}}}
		var res *http.Response
		res, err = client.Get("https://" + ts.addr)
		if err == nil {
			body, _ = io.ReadAll(res.Body)
			res.Body.Close()
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || string(body) != "real site" {
		t.Fatalf("probe did not reach the real site: %v %q", err, body)
	}
}

func rootsOf(s *httptest.Server) *x509.CertPool {
	return s.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
}

func TestPlainTLSServerRefused(t *testing.T) {
	s := site(t)
	c := vless.ClientConfig{Addr: s.Listener.Addr().String(), ServerName: "example.com"}
	rand.Read(c.PublicKey[:])
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := vless.Dial(ctx, c, netip.MustParseAddrPort("127.0.0.1:1")); err == nil {
		t.Fatal("accepted a server that is not our REALITY server")
	}
}

func TestUnknownUserRejected(t *testing.T) {
	ts := echoServer(t)
	c := ts.client()
	c.User[0] ^= 1
	if _, err := dial(t, c); err == nil {
		t.Fatal("unknown VLESS user got a session")
	}
}

func TestHeaders(t *testing.T) {
	u, _ := vless.ParseUUID("b831381d-6324-4d53-ad4f-8cda48b30811")
	if u.String() != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		t.Fatalf("uuid round trip: %s", u)
	}
	var b bytes.Buffer
	req := vless.Request{User: u, Command: vless.CmdUDP, Dest: netip.MustParseAddrPort("198.51.100.10:3480")}
	vless.WriteRequest(&b, req)
	got, err := vless.ReadRequest(bufio.NewReader(&b))
	if err != nil || got != req {
		t.Fatalf("request round trip: %v %+v", err, got)
	}
}
