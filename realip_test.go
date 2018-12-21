package realip

import (
	"fmt"
	"net"
	"testing"

	"github.com/valyala/fasthttp"
)

func TestIsPrivateAddr(t *testing.T) {
	testData := map[string]bool{
		"127.0.0.0":   true,
		"10.0.0.0":    true,
		"169.254.0.0": true,
		"192.168.0.0": true,
		"::1":         true,
		"fc00::":      true,

		"172.15.0.0": false,
		"172.16.0.0": true,
		"172.31.0.0": true,
		"172.32.0.0": false,

		"147.12.56.11": false,
	}

	for addr, isLocal := range testData {
		isPrivate, err := isPrivateAddress(addr)
		if err != nil {
			t.Errorf("fail processing %s: %v", addr, err)
		}

		if isPrivate != isLocal {
			format := "%s should "
			if !isLocal {
				format += "not "
			}
			format += "be local address"

			t.Errorf(format, addr)
		}
	}
}

func TestRealIP(t *testing.T) {
	// Create type and function for testing
	type testIP struct {
		name     string
		request  *fasthttp.RequestCtx
		expected string
	}

	newRequest := func(remoteAddr, xRealIP string, xForwardedFor ...string) *fasthttp.RequestCtx {
		var ctx fasthttp.RequestCtx
		addr := &net.TCPAddr{
			IP: net.ParseIP(remoteAddr),
		}
		ctx.Init(&ctx.Request, addr, nil)

		if xRealIP != "" {
			ctx.Request.Header.Set("X-Real-IP", xRealIP)
		}

		for _, address := range xForwardedFor {
			ctx.Request.Header.Set("X-Forwarded-For", address)
		}

		return &ctx
	}

	// Create test data
	publicAddr1 := "144.12.54.87"
	publicAddr2 := "119.14.55.11"
	localAddr := "127.0.0.0"

	testData := []testIP{
		{
			name:     "No header",
			request:  newRequest(publicAddr1, ""),
			expected: publicAddr1,
		}, {
			name:     "Has X-Forwarded-For",
			request:  newRequest("", "", publicAddr1),
			expected: publicAddr1,
		}, {
			name:     "Has multiple X-Forwarded-For",
			request:  newRequest("", "", localAddr, publicAddr1, publicAddr2),
			expected: publicAddr2,
		}, {
			name:     "Has multiple address for X-Forwarded-For",
			request:  newRequest("", "", localAddr, fmt.Sprintf("%s,%s", publicAddr1, publicAddr2)),
			expected: publicAddr1,
		}, {
			name:     "Has X-Real-IP",
			request:  newRequest("", publicAddr1),
			expected: publicAddr1,
		},
	}

	// Run test
	for _, v := range testData {
		if actual := FromRequest(v.request); v.expected != actual {
			t.Errorf("%s: expected %s but get %s", v.name, v.expected, actual)
		}
	}
}
