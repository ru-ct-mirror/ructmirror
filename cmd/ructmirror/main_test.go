package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"testing"
)

// The client hands back an HTTP failure wrapped as
// "GET ... failed after N attempts: %w" around net/http's *url.Error, which
// wraps the dialer's *net.OpError, which wraps the resolver's answer.
func TestHostNotFound(t *testing.T) {
	wrap := func(inner error) error {
		return fmt.Errorf("GET https://x/ct/v1/get-sth failed after 7 attempts: %w",
			&url.Error{Op: "Get", URL: "https://x/ct/v1/get-sth", Err: &net.OpError{Op: "dial", Net: "tcp", Err: inner}})
	}
	if !hostNotFound(wrap(&net.DNSError{Err: "no such host", Name: "x", IsNotFound: true})) {
		t.Fatal("NXDOMAIN not recognised")
	}
	if hostNotFound(wrap(&net.DNSError{Err: "i/o timeout", Name: "x", IsTimeout: true})) {
		t.Fatal("a resolver timeout is not a missing host")
	}
	if hostNotFound(errors.New("GET https://x/: HTTP 503")) {
		t.Fatal("an HTTP error is not a missing host")
	}
}
