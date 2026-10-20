package realip

// Resolver map:
//   - Options / NewResolver: validate configuration once, at startup.
//   - (*Resolver).FromRequest: trust decision, starting from the TCP peer.
//   - X-Forwarded-For walk: right to left, one comma separated hop at a time.
//   - RFC 7239 Forwarded walk: right to left, quote aware, strict ABNF.
//   - Single value headers (X-Real-IP, CF-Connecting-IP, ...).
//
// Security model: every header is client controlled until a trusted proxy
// has written it. The only value a client cannot forge is the TCP peer
// address, so resolution always starts there and moves left through the
// header only while the hop that wrote the next value is trusted.

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/valyala/fasthttp"
)

// Header names accepted by Options.Header with a dedicated parser.
const (
	// HeaderXForwardedFor selects the de facto X-Forwarded-For list.
	HeaderXForwardedFor = "X-Forwarded-For"
	// HeaderForwarded selects the RFC 7239 Forwarded list.
	HeaderForwarded = "Forwarded"
)

// Options configures a Resolver.
//
// TrustedProxies lists the proxies allowed to set the client address, as
// CIDR blocks ("10.0.0.0/8", "2001:db8::/32") or single addresses
// ("192.0.2.10"). An empty list trusts nobody: the TCP peer is returned.
//
// Header names the one header the trusted proxies write. It must be the
// header your edge proxy overwrites or appends to; reading any other header
// lets clients forge their address. Empty means X-Forwarded-For.
// "Forwarded" uses RFC 7239 parsing. Any other name (for example X-Real-IP
// or CF-Connecting-IP) is read as a single IP value.
type Options struct {
	TrustedProxies []string
	Header         string
}

// clientWrittenHeaders are rejected as Options.Header: proxies forward them
// from the client as is, so they can never carry a trusted address.
var clientWrittenHeaders = []string{
	"Host", "Cookie", "Authorization", "User-Agent", "Referer", "Origin",
	"Content-Type", "Content-Length", "Connection", "Transfer-Encoding",
}

// headerMode tells FromRequest which parser the configured header needs.
type headerMode int

const (
	modeXForwardedFor headerMode = iota
	modeForwarded
	modeSingle
)

// Resolver returns the client IP of a fasthttp request while trusting only
// configured proxies. It is safe for concurrent use; it is immutable after
// NewResolver returns.
type Resolver struct {
	trusted []*net.IPNet
	header  []byte
	mode    headerMode
}

// NewResolver validates opts and returns a ready Resolver.
//
// It returns an error when a TrustedProxies entry is neither a CIDR nor an
// IP address, or when Header is not a valid HTTP field name. Validation
// happens here, not per request, so a bad configuration fails at startup
// instead of silently trusting or distrusting traffic.
func NewResolver(opts Options) (*Resolver, error) {
	trusted, err := parseTrustedProxies(opts.TrustedProxies)
	if err != nil {
		return nil, err
	}

	header := strings.TrimSpace(opts.Header)

	if header == "" {
		header = HeaderXForwardedFor
	}

	if !isToken(header) {
		return nil, fmt.Errorf("realip: invalid header name %q", opts.Header)
	}

	// These headers are written by the client and forwarded unchanged by
	// proxies, so reading an address from them is always spoofable.
	for _, clientHeader := range clientWrittenHeaders {
		if strings.EqualFold(header, clientHeader) {
			return nil, fmt.Errorf("realip: header %q is client controlled", opts.Header)
		}
	}

	r := &Resolver{
		trusted: trusted,
		header:  []byte(http.CanonicalHeaderKey(header)),
		mode:    modeSingle,
	}

	// Header names are case-insensitive (RFC 9110 section 5.1).
	switch {
	case strings.EqualFold(header, HeaderXForwardedFor):
		r.mode = modeXForwardedFor
	case strings.EqualFold(header, HeaderForwarded):
		r.mode = modeForwarded
	}

	return r, nil
}

// parseTrustedProxies turns CIDR or single address strings into networks.
// A single address becomes a /32 or /128 network so both forms share one
// containment check. It returns an error naming the first invalid entry.
func parseTrustedProxies(entries []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)

		if strings.ContainsRune(entry, '/') {
			_, network, err := net.ParseCIDR(entry)
			if err != nil {
				return nil, fmt.Errorf("realip: invalid trusted proxy %q: %v", entry, err)
			}

			// ParseCIDR keeps IPv4-mapped blocks ("::ffff:0.0.0.0/96") as 16
			// byte masks, but Contains applies them to IPv4 peers as IPv4
			// masks. Normalize to 4 bytes so the /0 check below sees the
			// prefix that Contains will really use.
			if ip4 := network.IP.To4(); ip4 != nil && len(network.Mask) == net.IPv6len {
				network = &net.IPNet{IP: ip4, Mask: network.Mask[12:]}
			}

			// A /0 block trusts every peer, which makes every header client
			// controlled again: that is the spoofing this type exists to stop.
			if ones, _ := network.Mask.Size(); ones == 0 {
				return nil, fmt.Errorf("realip: trusted proxy %q trusts every address", entry)
			}

			nets = append(nets, network)

			continue
		}

		ip := net.ParseIP(entry)
		if ip == nil {
			return nil, fmt.Errorf("realip: invalid trusted proxy %q", entry)
		}

		bits := 8 * net.IPv6len
		if ip4 := ip.To4(); ip4 != nil {
			ip, bits = ip4, 8*net.IPv4len
		}

		nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}

	return nets, nil
}

// FromRequest returns the client IP in canonical text form (net.IP.String).
//
// The TCP peer is returned unless it is a trusted proxy. For a trusted peer
// the configured header is read from the right: each hop a trusted proxy
// wrote is accepted, and the first hop that is not itself a trusted proxy
// is the client. Malformed, "unknown" or obfuscated hops stop the walk and
// the last verified address is returned, never a guessed one. The result is
// therefore always an IP address and never raw header text.
func (r *Resolver) FromRequest(ctx *fasthttp.RequestCtx) string {
	peer := ctx.RemoteIP()

	// Only the TCP peer is unforgeable. If it is not a trusted proxy, no
	// header value can be trusted, whatever it contains.
	if !r.isTrusted(peer) {
		return peer.String()
	}

	lines := r.headerLines(ctx)

	switch r.mode {
	case modeXForwardedFor:
		return walkHops(lines, peer, r.isTrusted, prevXForwardedForHop).String()
	case modeForwarded:
		return walkHops(lines, peer, r.isTrusted, prevForwardedHop).String()
	default:
		return singleValue(lines, peer).String()
	}
}

// isTrusted reports whether ip belongs to a configured trusted proxy.
// net.IPNet.Contains also matches IPv4-mapped IPv6 peers against IPv4 blocks.
func (r *Resolver) isTrusted(ip net.IP) bool {
	for _, network := range r.trusted {
		if network.Contains(ip) {
			return true
		}
	}

	return false
}

// headerLines returns every field line of the configured header in receive
// order. Reading all lines matters: RFC 9110 section 5.3 makes repeated lines
// one comma joined list, and Peek would return only the first line, which is
// the one a client is most likely to have written.
func (r *Resolver) headerLines(ctx *fasthttp.RequestCtx) []string {
	var lines []string

	ctx.Request.Header.VisitAll(func(key, value []byte) {
		if bytes.EqualFold(key, r.header) {
			// value is only valid during the callback, so copy it.
			lines = append(lines, string(value))
		}
	})

	return lines
}

// prevHopFunc parses the hop at the end of s. It returns the text before
// that hop, the hop's IP (nil when the hop is not a usable IP address) and
// ok=false when s holds no further hop.
type prevHopFunc func(s string) (rest string, ip net.IP, ok bool)

// walkHops walks the header lines from the last hop to the first and
// returns the client address. last starts as the trusted peer and is moved
// left only after the current hop is proven to be a trusted proxy, so the
// returned address was always written by a trusted party (or is the peer).
func walkHops(lines []string, last net.IP, isTrusted func(net.IP) bool, prev prevHopFunc) net.IP {
	for i := len(lines) - 1; i >= 0; i-- {
		rest := lines[i]

		for {
			var (
				ip net.IP
				ok bool
			)

			rest, ip, ok = prev(rest)
			if !ok {
				break
			}

			// A hop we cannot read means the chain is broken here; the
			// closest verified address is the safest answer.
			if ip == nil {
				return last
			}

			if !isTrusted(ip) {
				return ip
			}

			last = ip
		}
	}

	// Every hop was a trusted proxy: the leftmost one is the client.
	return last
}

// singleValue reads a header that a trusted proxy overwrites with one IP,
// such as X-Real-IP. Exactly one line holding exactly one IP is accepted;
// anything else means the proxy did not replace a client supplied value,
// so the peer is returned instead.
func singleValue(lines []string, peer net.IP) net.IP {
	if len(lines) != 1 {
		return peer
	}

	ip := parseNodeIP(strings.TrimSpace(lines[0]))
	if ip == nil {
		return peer
	}

	return ip
}

// prevXForwardedForHop returns the last element of an X-Forwarded-For
// line. X-Forwarded-For has no RFC; real proxies write a bare IP, sometimes
// with a port ("192.0.2.1:8080", "[2001:db8::1]:443"). No quoting exists in
// this header, so a plain comma split is exact.
func prevXForwardedForHop(s string) (string, net.IP, bool) {
	rest, element, ok := prevListElement(s, func(s string) int { return strings.LastIndexByte(s, ',') })
	if !ok {
		return "", nil, false
	}

	return rest, parseNodeIP(element), true
}

// prevListElement returns the last non-empty element of an RFC 9110
// comma separated list and the text before it; lastComma finds the
// separator. Empty elements (",,") are skipped as the list syntax allows.
func prevListElement(s string, lastComma func(string) int) (rest, element string, ok bool) {
	for {
		s = strings.TrimRight(s, " \t")
		if s == "" {
			return "", "", false
		}

		cut := lastComma(s)
		element, rest = strings.TrimSpace(s[cut+1:]), ""

		if cut >= 0 {
			rest = s[:cut]
		}

		if element != "" {
			return rest, element, true
		}

		s = rest
	}
}

// parseNodeIP parses "ip", "ip:port", "[ipv6]" or "[ipv6]:port" and
// returns the IP in its shortest form (IPv4 as 4 bytes). It returns nil for
// anything else, including zones ("fe80::1%eth0"), which net.ParseIP rejects.
func parseNodeIP(node string) net.IP {
	host := node

	switch {
	case strings.HasPrefix(node, "["):
		end := strings.IndexByte(node, ']')
		if end < 0 {
			return nil
		}

		host = node[1:end]

		if after := node[end+1:]; after != "" && !validPortSuffix(after) {
			return nil
		}

		// Brackets are for IPv6 only (RFC 3986 section 3.2.2).
		if !strings.ContainsRune(host, ':') {
			return nil
		}

	case strings.Count(node, ":") == 1:
		cut := strings.IndexByte(node, ':')
		if !validPortSuffix(node[cut:]) {
			return nil
		}

		host = node[:cut]
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}

	return ip
}

// validPortSuffix reports whether s is ":" followed by a decimal port in
// 0..65535 (RFC 3986 port, bounded to what TCP can carry).
func validPortSuffix(s string) bool {
	if len(s) < 2 || s[0] != ':' || len(s) > 6 {
		return false
	}

	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}

	port, err := strconv.Atoi(s[1:])

	return err == nil && port <= 65535
}

// prevForwardedHop returns the last forwarded-element of an RFC 7239
// Forwarded line and the IP of its "for" parameter.
//
// The line is split from the right while tracking quoted-strings, so an
// unterminated quote a client put at the start cannot swallow the
// elements trusted proxies appended after it. Elements without "for", with
// "for=unknown", an obfuscated identifier ("_hidden") or any ABNF error
// yield a nil IP, which stops the walk.
func prevForwardedHop(s string) (string, net.IP, bool) {
	rest, element, ok := prevListElement(s, func(s string) int { return lastUnquotedIndex(s, ',') })
	if !ok {
		return "", nil, false
	}

	return rest, forwardedForIP(element), true
}

// lastUnquotedIndex returns the index of the last sep outside a
// quoted-string, or -1. Scanning backwards, a '"' toggles quoting unless it
// is escaped by an odd number of backslashes (RFC 9110 quoted-pair).
func lastUnquotedIndex(s string, sep byte) int {
	quoted := false

	for i := len(s) - 1; i >= 0; i-- {
		switch s[i] {
		case '"':
			backslashes := 0

			for j := i - 1; j >= 0 && s[j] == '\\'; j-- {
				backslashes++
			}

			if backslashes%2 == 0 {
				quoted = !quoted
			}
		case sep:
			if !quoted {
				return i
			}
		}
	}

	return -1
}

// errForwardedSyntax marks an element that does not match RFC 7239 ABNF.
var errForwardedSyntax = errors.New("realip: malformed Forwarded element")

// forwardedForIP returns the IP of the single "for" parameter of one
// forwarded-element, or nil when it is missing, repeated, not an IP or the
// element is malformed. RFC 7239 section 4: parameter names are
// case-insensitive and each may appear at most once per element.
func forwardedForIP(element string) net.IP {
	var (
		node    string
		hasNode bool
	)

	for element != "" {
		var (
			name, value string
			err         error
		)

		name, value, element, err = nextForwardedPair(element)
		if err != nil {
			return nil
		}

		if !strings.EqualFold(name, "for") {
			continue
		}

		if hasNode {
			return nil
		}

		node, hasNode = value, true
	}

	if !hasNode {
		return nil
	}

	return forwardedNodeIP(node)
}

// nextForwardedPair parses `token "=" ( token / quoted-string )` at the
// start of s, followed by an optional ";" and the remaining pairs. Optional
// whitespace around ";" is tolerated as common proxies emit it.
func nextForwardedPair(s string) (name, value, rest string, err error) {
	s = strings.TrimLeft(s, " \t")

	eq := strings.IndexByte(s, '=')
	if eq <= 0 || !isToken(s[:eq]) {
		return "", "", "", errForwardedSyntax
	}

	name, s = s[:eq], s[eq+1:]

	if strings.HasPrefix(s, `"`) {
		value, s, err = readQuotedString(s)
		if err != nil {
			return "", "", "", err
		}
	} else {
		end := strings.IndexByte(s, ';')
		if end < 0 {
			end = len(s)
		}

		value, s = strings.TrimRight(s[:end], " \t"), s[end:]

		if !isToken(value) {
			return "", "", "", errForwardedSyntax
		}
	}

	s = strings.TrimLeft(s, " \t")

	switch {
	case s == "":
		return name, value, "", nil
	case s[0] == ';':
		rest = s[1:]

		// A trailing ";" with nothing after it is not a forwarded-pair.
		if strings.TrimSpace(rest) == "" {
			return "", "", "", errForwardedSyntax
		}

		return name, value, rest, nil
	default:
		return "", "", "", errForwardedSyntax
	}
}

// readQuotedString reads an RFC 9110 quoted-string at the start of s and
// returns its unescaped content and the text after the closing quote.
func readQuotedString(s string) (value, rest string, err error) {
	var b strings.Builder

	for i := 1; i < len(s); i++ {
		c := s[i]

		switch {
		case c == '"':
			return b.String(), s[i+1:], nil
		case c == '\\':
			i++

			if i == len(s) || !isQuotedPairChar(s[i]) {
				return "", "", errForwardedSyntax
			}

			b.WriteByte(s[i])
		case isQdText(c):
			b.WriteByte(c)
		default:
			return "", "", errForwardedSyntax
		}
	}

	return "", "", errForwardedSyntax
}

// forwardedNodeIP parses an RFC 7239 section 6 node: IPv4address,
// "[" IPv6address "]", "unknown" or an obfuscated identifier, each with an
// optional ":" node-port. Only real IPs are returned; "unknown" and
// obfuscated nodes return nil because they cannot identify a client.
func forwardedNodeIP(node string) net.IP {
	host, port := node, ""

	if strings.HasPrefix(node, "[") {
		end := strings.IndexByte(node, ']')
		if end < 0 {
			return nil
		}

		host, port = node[1:end], node[end+1:]

		// RFC 7239 requires IPv6 to be bracketed, and only IPv6.
		if !strings.ContainsRune(host, ':') {
			return nil
		}
	} else {
		if cut := strings.IndexByte(node, ':'); cut >= 0 {
			host, port = node[:cut], node[cut:]
		}

		// An unbracketed IPv6 address is invalid in RFC 7239.
		if strings.ContainsRune(host, ':') {
			return nil
		}
	}

	if port != "" && !validNodePort(port) {
		return nil
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}

	if ip4 := ip.To4(); ip4 != nil {
		return ip4
	}

	return ip
}

// validNodePort reports whether s is ":" followed by an RFC 7239 node-port:
// a decimal port (bounded to 65535) or an obfuscated port "_" 1*(ALPHA /
// DIGIT / "." / "_" / "-").
func validNodePort(s string) bool {
	if len(s) > 1 && s[1] == '_' {
		return len(s) > 2 && isObfuscatedTail(s[2:])
	}

	return validPortSuffix(s)
}

// isObfuscatedTail reports whether s only holds ALPHA / DIGIT / "." / "_" / "-".
func isObfuscatedTail(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')

		if !alnum && c != '.' && c != '_' && c != '-' {
			return false
		}
	}

	return true
}

// isToken reports whether s is a non-empty RFC 9110 token.
func isToken(s string) bool {
	if s == "" {
		return false
	}

	for i := 0; i < len(s); i++ {
		if !isTokenChar(s[i]) {
			return false
		}
	}

	return true
}

// isTokenChar reports whether c is an RFC 9110 tchar.
func isTokenChar(c byte) bool {
	alnum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')

	return alnum || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0
}

// isQdText reports whether c may appear unescaped in an RFC 9110
// quoted-string: HTAB, SP, %x21, %x23-5B, %x5D-7E, obs-text.
func isQdText(c byte) bool {
	return c == '\t' || c == ' ' || c == 0x21 || (c >= 0x23 && c <= 0x5B) || (c >= 0x5D && c <= 0x7E) || c >= 0x80
}

// isQuotedPairChar reports whether c may follow a backslash in an RFC 9110
// quoted-pair: HTAB, SP, VCHAR, obs-text.
func isQuotedPairChar(c byte) bool {
	return c == '\t' || c == ' ' || (c >= 0x21 && c <= 0x7E) || c >= 0x80
}
