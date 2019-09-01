// Copyright 2015 The etcd Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netutil

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"reflect"
	"sort"
	"time"

	"go.etcd.io/etcd/pkg/types"

	"go.uber.org/zap"
)

// indirection for testing
var resolveTCPAddr = resolveTCPAddrDefault

const retryInterval = time.Second

// taken from go's ResolveTCP code but uses configurable ctx
func resolveTCPAddrDefault(ctx context.Context, addr string) ([]net.TCPAddr, error) {
	host, port, serr := net.SplitHostPort(addr)
	if serr != nil {
		return nil, serr
	}
	portnum, perr := net.DefaultResolver.LookupPort(ctx, "tcp", port)
	if perr != nil {
		return nil, perr
	}

	var addrs []net.TCPAddr
	if ip := net.ParseIP(host); ip != nil {
		addrs = append(addrs, net.TCPAddr{IP: ip, Port: portnum})
	} else {
		// Try as a DNS name.
		net.DefaultResolver = &net.Resolver{}
		ipss, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}

		for _, ip := range ipss {
			addrs = append(addrs, net.TCPAddr{IP: ip.IP, Port: portnum, Zone: ip.Zone})
		}
	}

	return addrs, nil
}

// resolveTCPAddrs is a convenience wrapper for net.ResolveTCPAddr.
// resolveTCPAddrs return a new set of url.URLs, in which all DNS hostnames
// are resolved.
func resolveTCPAddrs(ctx context.Context, lg *zap.Logger, urls [][]url.URL) ([][]url.URL, error) {
	newurls := make([][]url.URL, 0)
	for _, us := range urls {
		nus := make([]url.URL, len(us))
		for i, u := range us {
			nu, err := url.Parse(u.String())
			if err != nil {
				return nil, fmt.Errorf("failed to parse %q (%v)", u.String(), err)
			}
			nus[i] = *nu
		}
		resolvednus := make([]url.URL, 0, len(nus))
		for _, u := range nus {
			h, err := resolveURL(ctx, lg, u)
			if err != nil {
				return nil, fmt.Errorf("failed to resolve %q (%v)", u.String(), err)
			}
			for _, host := range h {
				if host != "" {
					resolved := u
					resolved.Host = host
					resolvednus = append(resolvednus, resolved)
				}
			}
		}
		newurls = append(newurls, resolvednus)
	}
	return newurls, nil
}

func resolveURL(ctx context.Context, lg *zap.Logger, u url.URL) ([]string, error) {
	if u.Scheme == "unix" || u.Scheme == "unixs" {
		// unix sockets don't resolve over TCP
		return nil, nil
	}
	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		lg.Warn(
			"failed to parse URL Host while resolving URL",
			zap.String("url", u.String()),
			zap.String("host", u.Host),
			zap.Error(err),
		)
		return nil, err
	}
	if host == "localhost" || net.ParseIP(host) != nil {
		return []string{u.Host}, nil
	}
	for ctx.Err() == nil {
		tcpAddrs, err := resolveTCPAddr(ctx, u.Host)
		if err == nil {
			tcpStrings := make([]string, len(tcpAddrs))
			for i := range tcpAddrs {
				tcpStrings[i] = tcpAddrs[i].String()
			}

			lg.Info(
				"resolved URL Host",
				zap.String("url", u.String()),
				zap.String("host", u.Host),
				zap.Strings("resolved-addrs", tcpStrings),
			)
			return tcpStrings, nil
		}

		lg.Warn(
			"failed to resolve URL Host",
			zap.String("url", u.String()),
			zap.String("host", u.Host),
			zap.Duration("retry-interval", retryInterval),
			zap.Error(err),
		)

		select {
		case <-ctx.Done():
			lg.Warn(
				"failed to resolve URL Host; returning",
				zap.String("url", u.String()),
				zap.String("host", u.Host),
				zap.Duration("retry-interval", retryInterval),
				zap.Error(err),
			)
			return nil, err
		case <-time.After(retryInterval):
		}
	}
	return nil, ctx.Err()
}

// urlsEqual checks equality of url.URLS between two arrays.
// This check pass even if an URL is in hostname and opposite is in IP address.
func urlsEqual(ctx context.Context, lg *zap.Logger, a []url.URL, b []url.URL) (bool, error) {
	if len(a) != len(b) {
		return false, fmt.Errorf("len(%q) != len(%q)", urlsToStrings(a), urlsToStrings(b))
	}
	urls, err := resolveTCPAddrs(ctx, lg, [][]url.URL{a, b})
	if err != nil {
		return false, err
	}
	fmt.Printf("######## comparing %+v to %+v\n", urls[0], urls[1])
	preva, prevb := a, b
	a, b = urls[0], urls[1]
	sort.Sort(types.URLs(a))
	sort.Sort(types.URLs(b))
	for i := range a {
		if !reflect.DeepEqual(a[i], b[i]) {
			return false, fmt.Errorf("%q(resolved from %q) != %q(resolved from %q)",
				a[i].String(), preva[i].String(),
				b[i].String(), prevb[i].String(),
			)
		}
	}
	return true, nil
}

// URLStringsEqual returns "true" if given URLs are valid
// and resolved to same IP addresses. Otherwise, return "false"
// and error, if any.
func URLStringsEqual(ctx context.Context, lg *zap.Logger, a []string, b []string) (bool, error) {
	if len(a) != len(b) {
		return false, fmt.Errorf("len(%q) != len(%q)", a, b)
	}
	urlsA := make([]url.URL, 0)
	for _, str := range a {
		u, err := url.Parse(str)
		if err != nil {
			return false, fmt.Errorf("failed to parse %q", str)
		}
		urlsA = append(urlsA, *u)
	}
	urlsB := make([]url.URL, 0)
	for _, str := range b {
		u, err := url.Parse(str)
		if err != nil {
			return false, fmt.Errorf("failed to parse %q", str)
		}
		urlsB = append(urlsB, *u)
	}
	if lg == nil {
		lg, _ = zap.NewProduction()
		if lg == nil {
			lg = zap.NewExample()
		}
	}
	return urlsEqual(ctx, lg, urlsA, urlsB)
}

func urlsToStrings(us []url.URL) []string {
	rs := make([]string, len(us))
	for i := range us {
		rs[i] = us[i].String()
	}
	return rs
}

func IsNetworkTimeoutError(err error) bool {
	nerr, ok := err.(net.Error)
	return ok && nerr.Timeout()
}
