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

// Header may return multiple IP addresses in the format: "client IP, proxy 1 IP, proxy 2 IP", so we take the the first one.
var xForwardedForHeader = http.CanonicalHeaderKey("X-Forwarded-For")
var xForwardedHeader = http.CanonicalHeaderKey("X-Forwarded")
var forwardedForHeader = http.CanonicalHeaderKey("Forwarded-For")
var forwardedHeader = http.CanonicalHeaderKey("Forwarded")


// Standard headers used by Amazon EC2, Heroku, and others
var xClientIPHeader = http.CanonicalHeaderKey("X-Client-IP")

// Nginx proxy/FastCGI
var xRealIPHeader = http.CanonicalHeaderKey("X-Real-IP")

// Cloudflare.
// @see https://support.cloudflare.com/hc/en-us/articles/200170986-How-does-Cloudflare-handle-HTTP-Request-headers-
// CF-Connecting-IP - applied to every request to the origin.
var cfConnectingIPHeader = http.CanonicalHeaderKey("CF-Connecting-IP")

// Fastly CDN and Firebase hosting header when forwared to a cloud function
var fastlyClientIPHeader = http.CanonicalHeaderKey("Fastly-Client-Ip")

// Akamai and Cloudflare
var trueClientIPHeader = http.CanonicalHeaderKey("True-Client-Ip")

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
	xClientIP := ctx.Request.Header.Peek(xClientIPHeader)
	if xClientIP != nil {
		return string(xClientIP)
	}

	xForwardedFor := ctx.Request.Header.Peek(xForwardedForHeader)
	if xForwardedFor != nil {
		requestIP, err := RetrieveForwardedIP(string(xForwardedFor))
		if err == nil {
			return requestIP
		}
	}


	cfConnectingIP := ctx.Request.Header.Peek(cfConnectingIPHeader)
	if cfConnectingIP != nil {
		return string(cfConnectingIP)
	}

	fastlyClientIP := ctx.Request.Header.Peek(fastlyClientIPHeader)
	if fastlyClientIP != nil {
		return string(fastlyClientIP)
	}

	trueClientIP := ctx.Request.Header.Peek(trueClientIPHeader)
	if trueClientIP != nil {
		return string(trueClientIP)
	}

	xRealIP := ctx.Request.Header.Peek(xRealIPHeader)
	if xRealIP != nil {
		return string(xRealIP)
	}

	xForwarded := ctx.Request.Header.Peek(xForwardedHeader)
	if xForwarded != nil {
		requestIP, err := RetrieveForwardedIP(string(xForwarded))
		if err == nil {
			return requestIP
		}
	}

	forwardedFor := ctx.Request.Header.Peek(forwardedForHeader)
	if forwardedFor != nil {
		requestIP, err := RetrieveForwardedIP(string(forwardedFor))
		if err == nil {
			return requestIP
		}
	}

	forwarded := ctx.Request.Header.Peek(forwardedHeader)
	if forwardedFor != nil {
		requestIP, err := RetrieveForwardedIP(string(forwarded))
		if err == nil {
			return requestIP
		}
	}

	var remoteIP string
	remoteAddr := ctx.RemoteAddr().String()

	if strings.ContainsRune(remoteAddr, ':') {
		remoteIP, _, _ = net.SplitHostPort(remoteAddr)
	} else {
		remoteIP = remoteAddr
	}
	return remoteIP
}

func RetrieveForwardedIP(forwardedHeader string) (string, error) {
	for _, address := range strings.Split(forwardedHeader, ",") {
		if len(address) > 0 {
			address = strings.TrimSpace(address)
			isPrivate, err := isPrivateAddress(address)
			if !isPrivate && err == nil {
				return address, nil
			} else if isPrivate && err == nil {
				return "", errors.New("forwarded ip is private")
			} else {
				return "", err
			}
		}
	}
	return "", errors.New("empty or invalid forwarded header")
}