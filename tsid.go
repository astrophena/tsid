// © 2021 Ilya Mateyko. All rights reserved.
// Use of this source code is governed by the ISC
// license that can be found in the LICENSE.md file.

// Package tsid is a Caddy plugin that allows access only to
// requests coming from the Tailscale network and allows to identify
// users behind these requests by setting some Caddy placeholders.
package tsid

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"sync"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"tailscale.com/client/local"
	"tailscale.com/net/tsaddr"
)

func init() {
	caddy.RegisterModule(new(Middleware))
	httpcaddyfile.RegisterHandlerDirective("tsid", parseCaddyfileHandler)
	httpcaddyfile.RegisterDirectiveOrder("tsid", httpcaddyfile.After, "basicauth")
}

func parseCaddyfileHandler(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	m := new(Middleware)
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return m, err
}

// Middleware is a Caddy HTTP handler that allows requests only from
// the Tailscale network and sets placeholders based on the Tailscale
// node information.
type Middleware struct {
	init sync.Once
	lc   *local.Client
}

// CaddyModule returns the Caddy module information.
func (*Middleware) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.tsid",
		New: func() caddy.Module { return new(Middleware) },
	}
}

// UnmarshalCaddyfile implements the [caddyfile.Unmarshaler] interface.
func (_ *Middleware) UnmarshalCaddyfile(d *caddyfile.Dispenser) error { return nil }

func (m *Middleware) localClient() *local.Client {
	m.init.Do(func() {
		m.lc = new(local.Client)
	})
	return m.lc
}

var (
	errNotTailscaleIP = errors.New("not a Tailscale IP")
	errNotAuthorized  = errors.New("not authorized")
)

// ServeHTTP implements the [caddyhttp.MiddlewareHandler] interface.
func (m *Middleware) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	ipStr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	if !tsaddr.IsTailscaleIP(ip) {
		return caddyhttp.Error(http.StatusForbidden, errNotTailscaleIP)
	}

	whois, err := m.localClient().WhoIs(r.Context(), r.RemoteAddr)
	if err != nil {
		if errors.Is(err, local.ErrPeerNotFound) {
			return caddyhttp.Error(http.StatusForbidden, errNotAuthorized)
		}
		return caddyhttp.Error(http.StatusInternalServerError, err)
	}

	// User information.
	caddyhttp.SetVar(r.Context(), "tailscale.id", whois.UserProfile.ID.String())
	caddyhttp.SetVar(r.Context(), "tailscale.name", whois.UserProfile.DisplayName)
	caddyhttp.SetVar(r.Context(), "tailscale.email", whois.UserProfile.LoginName)
	caddyhttp.SetVar(r.Context(), "tailscale.profile_pic_url", whois.UserProfile.ProfilePicURL)

	// Node information.
	caddyhttp.SetVar(r.Context(), "tailscale.node.id", whois.Node.ID.String())
	caddyhttp.SetVar(r.Context(), "tailscale.node.name", whois.Node.Name)
	caddyhttp.SetVar(r.Context(), "tailscale.node.os", whois.Node.Hostinfo.OS())
	caddyhttp.SetVar(r.Context(), "tailscale.node.os_version", whois.Node.Hostinfo.OSVersion())
	caddyhttp.SetVar(r.Context(), "tailscale.node.device_model", whois.Node.Hostinfo.DeviceModel())
	caddyhttp.SetVar(r.Context(), "tailscale.node.machine", whois.Node.Hostinfo.Machine())

	return next.ServeHTTP(w, r)
}

// Interface guards.
var (
	_ caddyhttp.MiddlewareHandler = (*Middleware)(nil)
	_ caddyfile.Unmarshaler       = (*Middleware)(nil)
)
