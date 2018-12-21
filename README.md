# FastHTTP - RealIP

[![GoDoc](https://godoc.org/github.com/Ferluci/fast-realip?status.svg)](https://godoc.org/github.com/Ferluci/fast-realip)

Go package that can be used to get client's real public IP from [FastHTTP]("https://github.com/valyala/fasthttp") request, which usually useful for logging HTTP server.

This is fork from [realip](https://github.com/tomasen/realip) for [FastHTTP]("https://github.com/valyala/fasthttp") with some imporvements.
### Feature

* Follows the rule of X-Real-IP
* Follows the rule of X-Forwarded-For
* Exclude local or private address

## Example

```go
package main

import (
	"github.com/Ferluci/fasthttp-realip"
	"github.com/valyala/fasthttp"
	"log"
)

func main() {
	handler := realipHandler
	if err := fasthttp.ListenAndServe(":8080", handler); err != nil {
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
