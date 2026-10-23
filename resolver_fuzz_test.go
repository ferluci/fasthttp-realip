//go:build go1.18
// +build go1.18

package realip

import (
	"net"
	"testing"

	"github.com/valyala/fasthttp"
)

// FuzzResolver checks the security invariants of Resolver on arbitrary
// header text: it never panics, it always returns an IP address (never raw
// header text) and an untrusted peer always wins over any header.
// The go1.18 build tag keeps the module testable on the go.mod minimum.
func FuzzResolver(f *testing.F) {
	seeds := []string{
		"198.51.100.7",
		"1.1.1.1, 198.51.100.7, 10.0.0.9",
		"[2001:db8::7]:443",
		`for="[2001:db8:cafe::17]:4711";proto=https`,
		`for="1.1.1.1, for=198.51.100.7`,
		`for=198.51.100.7;ext="a\",b"`,
		"for=_hidden, for=unknown",
		"",
	}

	for _, seed := range seeds {
		f.Add(seed)
	}

	resolvers := make([]*Resolver, 0, 3)

	for _, header := range []string{HeaderXForwardedFor, HeaderForwarded, "X-Real-IP"} {
		r, err := NewResolver(Options{TrustedProxies: []string{"10.0.0.0/8"}, Header: header})
		if err != nil {
			f.Fatal(err)
		}

		resolvers = append(resolvers, r)
	}

	f.Fuzz(func(t *testing.T, value string) {
		for _, r := range resolvers {
			for _, peer := range []string{"10.0.0.2", "203.0.113.9"} {
				var ctx fasthttp.RequestCtx

				ctx.Init(&ctx.Request, &net.TCPAddr{IP: net.ParseIP(peer)}, nil)
				ctx.Request.Header.Set(string(r.header), value)

				actual := r.FromRequest(&ctx)

				if net.ParseIP(actual) == nil {
					t.Fatalf("%s %q: result %q is not an IP", r.header, value, actual)
				}

				if peer == "203.0.113.9" && actual != peer {
					t.Fatalf("%s %q: untrusted peer overridden by %q", r.header, value, actual)
				}
			}
		}
	})
}
