# FastHTTP - RealIP

[![GoDoc](https://godoc.org/github.com/Ferluci/fast-realip?status.svg)](https://godoc.org/github.com/Ferluci/fast-realip)

Go package that can be used to get client's real public IP from [Fast HTTP](https://github.com/valyala/fasthttp) request, which usually useful for logging HTTP server.

This is fork from [realip](https://github.com/tomasen/realip) for [Fast HTTP](https://github.com/valyala/fasthttp) with some imporvements.
### Feature

* Follows the rule of X-Real-IP
* Follows the rule of X-Forwarded-For
* Exclude local or private address


## How It Works

It looks for specific headers in the request and falls back to some defaults if they do not exist.

The user ip is determined by the following order:

1. `X-Client-IP`  
2. `X-Forwarded-For` (Header may return multiple IP addresses in the format: "client IP, proxy 1 IP, proxy 2 IP", so we take the the first one.)
3. `CF-Connecting-IP` (Cloudflare)
4. `Fastly-Client-Ip` (Fastly CDN and Firebase hosting header when forwared to a cloud function)
5. `True-Client-Ip` (Akamai and Cloudflare)
6. `X-Real-IP` (Nginx proxy/FastCGI)
7. `X-Forwarded`, `Forwarded-For` and `Forwarded` (Variations of #2)
8. `ctx.RemoteAddr().String()`

## Install
```go
go get -u github.com/valyala/fasthttp
```
## Example

```go
package main

import (   
    "log"
    "github.com/valyala/fasthttp"
    "github.com/Ferluci/fast-realip"
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

## Developing

Commited code must pass:

* [golint](https://github.com/golang/lint)
* [go vet](https://godoc.org/golang.org/x/tools/cmd/vet)
* [gofmt](https://golang.org/cmd/gofmt)
* [go test](https://golang.org/cmd/go/#hdr-Test_packages):
