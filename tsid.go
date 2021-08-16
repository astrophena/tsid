// © 2021 Ilya Mateyko. All rights reserved.
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE.md file.

// Package tsid is a Caddy plugin that restricts access only to
// requests coming from the Tailscale network and allows to identify
// users behind these requests by setting some Caddy placeholders.
package tsid

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"inet.af/netaddr"
	"tailscale.com/client/tailscale"
	"tailscale.com/net/tsaddr"
)

func init() {
	caddy.RegisterModule(&Middleware{})
	httpcaddyfile.RegisterHandlerDirective("tsid", parseCaddyfileHandler)
}

// CaddyModule returns the Caddy module information.
func (Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tsid",
		New: func() caddy.Module { return &Middleware{} },
	}
}

// Middleware is a Caddy HTTP handler that allows requests only from
// the Tailscale network and sets placeholders based on the Tailscale
// node information.
type Middleware struct{}

// ServeHTTP implements the caddyhttp.MiddlewareHandler interface.
func (Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	ip, err := netaddr.ParseIP(ipStr)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	if !tsaddr.IsTailscaleIP(ip) {
		return caddyhttp.Error(http.StatusForbidden, errors.New("not a Tailscale IP"))
	}

	whois, err := tailscale.WhoIs(context.Background(), r.RemoteAddr)
	if err != nil {
		if strings.Contains(err.Error(), "no match for IP:port") {
			return caddyhttp.Error(http.StatusForbidden, errors.New("not authorized"))
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	caddyhttp.SetVar(r.Context(), "tailscale.name", whois.UserProfile.DisplayName)
	caddyhttp.SetVar(r.Context(), "tailscale.email", whois.UserProfile.LoginName)

	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements the caddyfile.Unmarshaler interface.
func (Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

// parseCaddyfileHandler unmarshals tokens from h into a new middleware handler value.
func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := &Middleware{}
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Interface guards.
var (
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
