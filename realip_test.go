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

	newRequest := func(remoteAddr string, headers map[string]string) *fasthttp.RequestCtx {
		var ctx fasthttp.RequestCtx
		addr := &net.TCPAddr{
			IP: net.ParseIP(remoteAddr),
		}
		ctx.Init(&ctx.Request, addr, nil)

		for header, value := range headers {
			ctx.Request.Header.Set(header, value)
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
			request:  newRequest(publicAddr1, map[string]string{}),
			expected: publicAddr1,
		},
		{
			name:     "Has X-Forwarded-For",
			request:  newRequest("", map[string]string{"X-Forwarded-For": publicAddr1}),
			expected: publicAddr1,
		},
		{
			name:     "Has multiple X-Forwarded-For",
			request:  newRequest("", map[string]string{
				"X-Forwarded-For": fmt.Sprintf("%s,%s,%s", publicAddr2, publicAddr1, localAddr),
			}),
			expected: publicAddr2,
		},
		{
			name:     "Has X-Real-IP",
			request:  newRequest("", map[string]string{"X-Real-IP": publicAddr1}),
			expected: publicAddr1,
		},
		{
			name:     "Has multiple X-Forwarded-For and X-Real-IP",
			request:  newRequest("", map[string]string{
				"X-Real-IP": publicAddr2,
				"X-Forwarded-For": fmt.Sprintf("%s,%s", publicAddr1, localAddr),
			}),
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
