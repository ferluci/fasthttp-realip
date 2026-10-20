# FastHTTP - RealIP

[![GoDoc](https://godoc.org/github.com/ferluci/fast-realip?status.svg)](https://godoc.org/github.com/ferluci/fast-realip)

Go package that can be used to get client's real public IP from [Fast HTTP](https://github.com/valyala/fasthttp) request, which usually useful for logging HTTP server.

This is fork from [realip](https://github.com/tomasen/realip) for [Fast HTTP](https://github.com/valyala/fasthttp) with some imporvements.
### Feature

* Follows the rule of X-Real-IP
* Follows the rule of X-Forwarded-For
* Exclude local or private address
* `Resolver`: trusted proxy aware resolution that clients cannot spoof
  (`X-Forwarded-For`, RFC 7239 `Forwarded` or a single value header such as
  `X-Real-IP` / `CF-Connecting-IP`)


## How It Works

> **Security:** `FromRequest` below trusts headers that any client can set.
> Use it for display or logging only. For access control, rate limiting or
> audit records use [`Resolver`](#trusted-proxy-resolver), see
> [Security](#security).

It looks for specific headers in the request and falls back to some defaults if they do not exist.

The user ip is determined by the following order:

1. `X-Client-IP`
2. `X-Original-Forwarded-For`
3. `X-Forwarded-For` (Header may return multiple IP addresses in the format: "client IP, proxy 1 IP, proxy 2 IP", so we take the the first one.)
4. `CF-Connecting-IP` (Cloudflare)
5. `Fastly-Client-Ip` (Fastly CDN and Firebase hosting header when forwared to a cloud function)
6. `True-Client-Ip` (Akamai and Cloudflare)
7. `X-Real-IP` (Nginx proxy/FastCGI)
8. `X-Forwarded`, `Forwarded-For` and `Forwarded` (Variations of #2)
9. `ctx.RemoteAddr().String()`

## Install
```go
go get -u github.com/ferluci/fast-realip
```
## Example

```go
package main

import (
    "log"
    "github.com/valyala/fasthttp"
    "github.com/ferluci/fast-realip"
)

func main() {
    if err := fasthttp.ListenAndServe(":8080", realipHandler); err != nil {
        log.Fatalf("Error in ListenAndServe: %s", err)
    }
}

func realipHandler(ctx *fasthttp.RequestCtx) {
    clientIP := realip.FromRequest(ctx)
    log.Println("GET / from", clientIP)
}


```

## Trusted Proxy Resolver

`Resolver` returns the client IP while trusting only the proxies you list.
Build it once at startup and share it; it is safe for concurrent use.

```go
package main

import (
    "log"

    "github.com/ferluci/fast-realip"
    "github.com/valyala/fasthttp"
)

func main() {
    // nginx / load balancer in 10.0.0.0/8 appends to X-Forwarded-For.
    resolver, err := realip.NewResolver(realip.Options{
        TrustedProxies: []string{"10.0.0.0/8", "2001:db8:ffff::/48"},
        Header:         realip.HeaderXForwardedFor, // the default
    })
    if err != nil {
        log.Fatal(err) // invalid CIDR, /0 block or unsafe header name
    }

    handler := func(ctx *fasthttp.RequestCtx) {
        log.Println("GET / from", resolver.FromRequest(ctx))
    }

    log.Fatal(fasthttp.ListenAndServe(":8080", handler))
}
```

`Options.Header` selects the one header your edge proxy writes:

| `Header` | Format | Typical proxy |
| --- | --- | --- |
| `X-Forwarded-For` (default) | comma list, `ip`, `ip:port`, `[ipv6]:port` | nginx `$proxy_add_x_forwarded_for`, most load balancers |
| `Forwarded` | RFC 7239, `for=192.0.2.1`, `for="[2001:db8::1]:443"` | proxies that emit RFC 7239 |
| any other name, e.g. `X-Real-IP`, `CF-Connecting-IP` | exactly one IP | proxies that overwrite the header (nginx `proxy_set_header X-Real-IP $remote_addr`, Cloudflare) |

`TrustedProxies` takes CIDR blocks or single addresses. An empty list
trusts nobody and always returns the TCP peer address.

How a request is resolved:

1. The TCP peer (`ctx.RemoteIP()`) is the starting point, because it is the
   only value a client cannot forge. If the peer is not a trusted proxy it is
   returned and no header is read.
2. All field lines of the configured header are read in order (repeated
   lines form one list, RFC 9110 section 5.3).
3. The list is walked from the right. Every hop written by a trusted proxy is
   accepted; the first hop that is not a trusted proxy is the client.
4. A hop that is not an IP (`unknown`, an obfuscated `_name`, a zone or any
   syntax error) stops the walk and the last verified address is returned.
   If every hop is trusted, the leftmost one is returned.
5. The result is always a parsed IP in canonical form, never header text.

## Security

The address a client reports in a header is client input. Only a proxy you
operate can turn it into something trustworthy, and only for the header it
writes.

`FromRequest` (kept unchanged for compatibility):

* reads `X-Client-IP` first and returns it verbatim, without checking that it
  is an IP; `CF-Connecting-IP`, `Fastly-Client-Ip`, `True-Client-Ip` and
  `X-Real-IP` are also returned verbatim;
* takes the **leftmost** `X-Forwarded-For` entry, which is the one the client
  writes;
* has no notion of trusted proxies, so any client can choose its own IP.

Do not use it for IP allow lists, rate limits, lockouts or audit logs unless
your edge proxy removes or overwrites every header listed in
[How It Works](#how-it-works).

`Resolver` guarantees:

* an untrusted peer can never be overridden by a header;
* only the configured header is read; other forwarding headers are ignored;
* `Forwarded` is parsed strictly by RFC 7239 (token / quoted-string values,
  quoted-pair escapes, one `for` per element, bracketed and quoted IPv6,
  quoted `ip:port`, numeric or obfuscated ports), and the list is split
  quote-aware from the right, so an unterminated quote sent by the client
  cannot hide elements appended by your proxies;
* configuration errors fail in `NewResolver`: invalid CIDR or IP, invalid
  header name, `/0` blocks (also IPv4-mapped ones such as `::ffff:0.0.0.0/96`)
  and client-written headers (`Host`, `Cookie`, `Authorization`,
  `User-Agent`, `Referer`, `Origin`, `Content-*`, `Connection`,
  `Transfer-Encoding`);
* cost is linear in header size, and header size is bounded by the fasthttp
  server read buffer.

Your responsibilities as operator:

* list only the proxies that really sit in front of the service and keep the
  blocks narrow; several wide blocks (for example `0.0.0.0/1` and
  `128.0.0.0/1`) still trust everyone;
* make the edge proxy append to `X-Forwarded-For` / `Forwarded`, or
  **overwrite** a single value header; if it forwards a client copy of a
  single value header, the result falls back to the proxy address (safe, but
  every client then shares one IP for per-IP limits);
* make trusted proxies write RFC 7239 compliant `for=` values when using
  `Forwarded`, otherwise the walk stops at them;
* behind a unix socket fasthttp reports the peer as `0.0.0.0`, which is
  trusted only if you list it.

## Developing

Committed code must pass (see `.github/workflows/go.yml`):

* [golangci-lint](https://golangci-lint.run) with `revive`, `gofmt`,
  `goimports`, `gocritic`, `misspell` and friends
* [go vet](https://pkg.go.dev/cmd/vet)
* `go test -race ./...`
* `go test -run '^$' -fuzz FuzzResolver -fuzztime 30s .` (Go 1.18+)

`realip_test.go` pins the legacy `FromRequest` behavior; `resolver_test.go`
and `resolver_fuzz_test.go` cover `Resolver`.
