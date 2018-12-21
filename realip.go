package realip

import (
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/valyala/fasthttp"
)

// Should use canonical format of the header key s
// https://golang.org/pkg/net/http/#CanonicalHeaderKey
var xForwardedFor = http.CanonicalHeaderKey("X-Forwarded-For")
var xRealIP = http.CanonicalHeaderKey("X-Real-IP")

var cidrs []*net.IPNet

func init() {
	maxCidrBlocks := []string{
		"127.0.0.1/8",    // localhost
		"10.0.0.0/8",     // 24-bit block
		"172.16.0.0/12",  // 20-bit block
		"192.168.0.0/16", // 16-bit block
		"169.254.0.0/16", // link local address
		"::1/128",        // localhost IPv6
		"fc00::/7",       // unique local address IPv6
		"fe80::/10",      // link local address IPv6
	}

	cidrs = make([]*net.IPNet, len(maxCidrBlocks))
	for i, maxCidrBlock := range maxCidrBlocks {
		_, cidr, _ := net.ParseCIDR(maxCidrBlock)
		cidrs[i] = cidr
	}
}

// isLocalAddress works by checking if the address is under private CIDR blocks.
// List of private CIDR blocks can be seen on :
//
// https://en.wikipedia.org/wiki/Private_network
//
// https://en.wikipedia.org/wiki/Link-local_address
func isPrivateAddress(address string) (bool, error) {
	ipAddress := net.ParseIP(address)
	if ipAddress == nil {
		return false, errors.New("address is not valid")
	}

	for i := range cidrs {
		if cidrs[i].Contains(ipAddress) {
			return true, nil
		}
	}

	return false, nil
}

// FromRequest returns client's real public IP address from http request headers.
func FromRequest(ctx *fasthttp.RequestCtx) string {
	// Fetch header value
	xRealIP := ctx.Request.Header.Peek(xRealIP)
	xForwardedFor := ctx.Request.Header.Peek(xForwardedFor)

	// If both empty, return IP from remote address
	if xRealIP == nil && xForwardedFor == nil {
		// If there are colon in remote address, remove the port number
		// otherwise, return remote address as is
		var remoteIP string
		remoteAddr := ctx.RemoteAddr().String()

		if strings.ContainsRune(remoteAddr, ':') {
			remoteIP, _, _ = net.SplitHostPort(remoteAddr)
		} else {
			remoteIP = remoteAddr
		}
		return remoteIP
	}

	xForwardedForStr := string(xForwardedFor)
	// Check list of IP in X-Forwarded-For and return the first global address
	for _, address := range strings.Split(xForwardedForStr, ",") {
		if len(address) > 0 {
			address = strings.TrimSpace(address)
			isPrivate, err := isPrivateAddress(address)
			if !isPrivate && err == nil {
				return address
			}
		}
	}

	// If nothing succeed, return X-Real-IP
	return string(xRealIP)
}
