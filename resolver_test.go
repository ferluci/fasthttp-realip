package realip

import (
	"bufio"
	"net"
	"strings"
	"testing"

	"github.com/valyala/fasthttp"
)

// header is one field line; a slice keeps repeated lines and their order.
type header struct {
	name, value string
}

type testResolve struct {
	name     string
	peer     string
	headers  []header
	expected string
}

// newResolverRequest builds a request whose TCP peer is peer and whose header
// lines are added in order, so repeated lines stay separate as on the wire.
func newResolverRequest(peer string, headers []header) *fasthttp.RequestCtx {
	var ctx fasthttp.RequestCtx

	ctx.Init(&ctx.Request, &net.TCPAddr{IP: net.ParseIP(peer), Port: 40000}, nil)

	for _, h := range headers {
		ctx.Request.Header.Add(h.name, h.value)
	}

	return &ctx
}

// mustResolver fails the test when opts are rejected.
func mustResolver(t *testing.T, opts Options) *Resolver {
	t.Helper()

	r, err := NewResolver(opts)
	if err != nil {
		t.Fatalf("NewResolver(%+v): %v", opts, err)
	}

	return r
}

// runResolve checks every case against r.
func runResolve(t *testing.T, r *Resolver, cases []testResolve) {
	t.Helper()

	for _, v := range cases {
		if actual := r.FromRequest(newResolverRequest(v.peer, v.headers)); actual != v.expected {
			t.Errorf("%s: expected %s but get %s", v.name, v.expected, actual)
		}
	}
}

func TestNewResolverOptions(t *testing.T) {
	valid := []Options{
		{},
		{TrustedProxies: []string{"10.0.0.0/8", " 192.0.2.10 ", "2001:db8::/32", "::1"}},
		{Header: "forwarded"},
		{Header: "X-Real-IP"},
		{Header: "CF-Connecting-IP"},
		{TrustedProxies: []string{"::ffff:10.0.0.0/104"}},
	}

	for _, opts := range valid {
		if _, err := NewResolver(opts); err != nil {
			t.Errorf("%+v should be valid: %v", opts, err)
		}
	}

	invalid := []Options{
		{TrustedProxies: []string{""}},
		{TrustedProxies: []string{"10.0.0.0/33"}},
		{TrustedProxies: []string{"proxy.example"}},
		{TrustedProxies: []string{"0.0.0.0/0"}},
		{TrustedProxies: []string{"::/0"}},
		{TrustedProxies: []string{"::ffff:0.0.0.0/96"}},
		{TrustedProxies: []string{"::ffff:0:0/96"}},
		{Header: "Host"},
		{Header: "cookie"},
		{Header: "X Forwarded For"},
		{Header: "X-Forwarded-For:"},
	}

	for _, opts := range invalid {
		if _, err := NewResolver(opts); err == nil {
			t.Errorf("%+v should be rejected", opts)
		}
	}
}

func TestResolverNoTrustedProxies(t *testing.T) {
	r := mustResolver(t, Options{})

	runResolve(t, r, []testResolve{
		{
			name:     "No header",
			peer:     "203.0.113.9",
			expected: "203.0.113.9",
		},
		{
			name: "Spoofed headers are ignored",
			peer: "203.0.113.9",
			headers: []header{
				{"X-Forwarded-For", "1.1.1.1"},
				{"X-Client-IP", "1.1.1.1"},
				{"X-Real-IP", "1.1.1.1"},
				{"Forwarded", "for=1.1.1.1"},
			},
			expected: "203.0.113.9",
		},
		{
			name:     "IPv6 peer",
			peer:     "2001:db8::1",
			headers:  []header{{"X-Forwarded-For", "1.1.1.1"}},
			expected: "2001:db8::1",
		},
	})
}

// TestResolverMappedTrustedBlock checks that an IPv4-mapped trusted block
// covers exactly its IPv4 range, not every IPv4 address.
func TestResolverMappedTrustedBlock(t *testing.T) {
	r := mustResolver(t, Options{TrustedProxies: []string{"::ffff:10.0.0.0/104"}})

	runResolve(t, r, []testResolve{
		{
			name:     "Mapped block trusts its IPv4 range",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "198.51.100.7"}},
			expected: "198.51.100.7",
		},
		{
			name:     "Mapped block does not trust other IPv4",
			peer:     "203.0.113.9",
			headers:  []header{{"X-Forwarded-For", "6.6.6.6"}},
			expected: "203.0.113.9",
		},
	})
}

func TestResolverXForwardedFor(t *testing.T) {
	r := mustResolver(t, Options{TrustedProxies: []string{"10.0.0.0/8", "2001:db8:ffff::/48"}})

	runResolve(t, r, []testResolve{
		{
			name:     "Untrusted peer ignores header",
			peer:     "203.0.113.9",
			headers:  []header{{"X-Forwarded-For", "198.51.100.7"}},
			expected: "203.0.113.9",
		},
		{
			name:     "Trusted peer, one hop",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "198.51.100.7"}},
			expected: "198.51.100.7",
		},
		{
			name:     "Client prefix is not trusted",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "1.1.1.1, 198.51.100.7"}},
			expected: "198.51.100.7",
		},
		{
			name:     "Trusted hops are skipped",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "1.1.1.1, 198.51.100.7, 10.0.0.9, 10.0.0.8"}},
			expected: "198.51.100.7",
		},
		{
			name: "Repeated lines form one list",
			peer: "10.0.0.2",
			headers: []header{
				{"X-Forwarded-For", "1.1.1.1"},
				{"X-Forwarded-For", "198.51.100.7, 10.0.0.9"},
			},
			expected: "198.51.100.7",
		},
		{
			name:     "Ports and brackets",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "[2001:db8::7]:443, 10.0.0.9:8080"}},
			expected: "2001:db8::7",
		},
		{
			name:     "IPv6 trusted hop",
			peer:     "2001:db8:ffff::1",
			headers:  []header{{"X-Forwarded-For", "198.51.100.7, 2001:db8:ffff::2"}},
			expected: "198.51.100.7",
		},
		{
			name:     "IPv4-mapped peer matches IPv4 block",
			peer:     "::ffff:10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "198.51.100.7"}},
			expected: "198.51.100.7",
		},
		{
			name:     "Empty elements are skipped",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", " , 198.51.100.7 ,, "}},
			expected: "198.51.100.7",
		},
		{
			name:     "Garbage hop returns peer",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "198.51.100.7, <script>"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Garbage after trusted hop returns that hop",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "unknown, 10.0.0.9"}},
			expected: "10.0.0.9",
		},
		{
			name:     "All hops trusted returns leftmost",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "10.0.0.7, 10.0.0.9"}},
			expected: "10.0.0.7",
		},
		{
			name:     "No header returns peer",
			peer:     "10.0.0.2",
			expected: "10.0.0.2",
		},
		{
			name:     "Zone is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "fe80::1%eth0"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Bad port is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "198.51.100.7:99999"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Bracketed IPv4 is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "[198.51.100.7]"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Other headers are not read",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Client-IP", "1.1.1.1"}, {"X-Real-IP", "1.1.1.1"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Canonical output",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "2001:DB8:0:0:0:0:0:7"}},
			expected: "2001:db8::7",
		},
	})
}

func TestResolverForwarded(t *testing.T) {
	r := mustResolver(t, Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: HeaderForwarded})

	runResolve(t, r, []testResolve{
		{
			name:     "Untrusted peer ignores header",
			peer:     "203.0.113.9",
			headers:  []header{{"Forwarded", "for=198.51.100.7"}},
			expected: "203.0.113.9",
		},
		{
			name:     "RFC 7239 example with other parameters",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", "for=192.0.2.60;proto=http;by=203.0.113.43"}},
			expected: "192.0.2.60",
		},
		{
			name:     "Quoted IPv6 with port",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", `For="[2001:db8:cafe::17]:4711"`}},
			expected: "2001:db8:cafe::17",
		},
		{
			name:     "Quoted IPv4 with port",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", `for="192.0.2.43:47011"`}},
			expected: "192.0.2.43",
		},
		{
			name:     "Client prefix is not trusted",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", "for=1.1.1.1, for=198.51.100.7, for=10.0.0.9"}},
			expected: "198.51.100.7",
		},
		{
			name: "Repeated lines form one list",
			peer: "10.0.0.2",
			headers: []header{
				{"Forwarded", "for=1.1.1.1"},
				{"Forwarded", "for=198.51.100.7;proto=https"},
			},
			expected: "198.51.100.7",
		},
		{
			name:     "Unterminated client quote cannot hide proxy element",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", `for="1.1.1.1, for=198.51.100.7`}},
			expected: "198.51.100.7",
		},
		{
			name:     "Comma inside quotes is not a separator",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", `for=198.51.100.7;ext="a,b"`}},
			expected: "198.51.100.7",
		},
		{
			name:     "Escaped quote inside quotes",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", `for=198.51.100.7;ext="a\",b"`}},
			expected: "198.51.100.7",
		},
		{
			name:     "Unknown node returns peer",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", "for=unknown"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Obfuscated node returns last trusted hop",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", "for=_hidden, for=10.0.0.9"}},
			expected: "10.0.0.9",
		},
		{
			name:     "Obfuscated port is accepted",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", `for="198.51.100.7:_p1"`}},
			expected: "198.51.100.7",
		},
		{
			name:     "Unbracketed IPv6 is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", `for="2001:db8::7"`}},
			expected: "10.0.0.2",
		},
		{
			name:     "Unquoted port is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", "for=198.51.100.7:80"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Duplicate for is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", "for=1.1.1.1;for=198.51.100.7"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Element without for returns peer",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", "proto=https;by=10.0.0.9"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Trailing semicolon is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"Forwarded", "for=198.51.100.7;"}},
			expected: "10.0.0.2",
		},
		{
			name:     "X-Forwarded-For is not read",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Forwarded-For", "198.51.100.7"}},
			expected: "10.0.0.2",
		},
	})
}

func TestResolverSingleHeader(t *testing.T) {
	r := mustResolver(t, Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: "X-Real-IP"})

	runResolve(t, r, []testResolve{
		{
			name:     "Untrusted peer ignores header",
			peer:     "203.0.113.9",
			headers:  []header{{"X-Real-IP", "198.51.100.7"}},
			expected: "203.0.113.9",
		},
		{
			name:     "Trusted peer",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Real-IP", " 198.51.100.7 "}},
			expected: "198.51.100.7",
		},
		{
			name:     "Header name is case-insensitive",
			peer:     "10.0.0.2",
			headers:  []header{{"x-real-ip", "198.51.100.7"}},
			expected: "198.51.100.7",
		},
		{
			name:     "List value is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Real-IP", "1.1.1.1, 198.51.100.7"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Repeated lines are rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Real-IP", "1.1.1.1"}, {"X-Real-IP", "198.51.100.7"}},
			expected: "10.0.0.2",
		},
		{
			name:     "Garbage is rejected",
			peer:     "10.0.0.2",
			headers:  []header{{"X-Real-IP", "junk"}},
			expected: "10.0.0.2",
		},
	})
}

// TestResolverWireRequest parses a raw request so repeated header lines go
// through fasthttp's own parser, not only through Header.Add.
func TestResolverWireRequest(t *testing.T) {
	r := mustResolver(t, Options{TrustedProxies: []string{"10.0.0.0/8"}})
	raw := "GET / HTTP/1.1\r\nHost: example\r\n" +
		"X-Forwarded-For: 1.1.1.1\r\n" +
		"X-Forwarded-For: 198.51.100.7\r\n\r\n"

	var ctx fasthttp.RequestCtx

	ctx.Init(&ctx.Request, &net.TCPAddr{IP: net.ParseIP("10.0.0.2")}, nil)

	if err := ctx.Request.Read(bufio.NewReader(strings.NewReader(raw))); err != nil {
		t.Fatalf("read request: %v", err)
	}

	if actual := r.FromRequest(&ctx); actual != "198.51.100.7" {
		t.Errorf("expected 198.51.100.7 but get %s", actual)
	}
}

func TestResolverNonTCPPeer(t *testing.T) {
	r := mustResolver(t, Options{TrustedProxies: []string{"10.0.0.0/8"}})

	var ctx fasthttp.RequestCtx

	ctx.Init(&ctx.Request, &net.UnixAddr{Name: "/tmp/sock", Net: "unix"}, nil)
	ctx.Request.Header.Set("X-Forwarded-For", "198.51.100.7")

	// fasthttp reports 0.0.0.0 for non-TCP peers; it is never trusted unless
	// configured, so the header must be ignored.
	if actual := r.FromRequest(&ctx); actual != "0.0.0.0" {
		t.Errorf("expected 0.0.0.0 but get %s", actual)
	}
}
