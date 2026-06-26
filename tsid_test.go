package tsid

import (
	"encoding/json"
	"mime"
	"testing"

	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"tailscale.com/tailcfg"
)

func TestUnmarshalCaddyfile(t *testing.T) {
	cases := map[string]struct {
		input    string
		wantCaps []tailcfg.PeerCapability
		wantErr  bool
	}{
		"empty": {
			input: "tsid",
		},
		"single line": {
			input: "tsid {\n\taccept_app_capabilities example.com/cap/foo example.com/cap/bar\n}",
			wantCaps: []tailcfg.PeerCapability{
				"example.com/cap/foo",
				"example.com/cap/bar",
			},
		},
		"repeated lines": {
			input: `tsid {
				accept_app_capabilities example.com/cap/foo
				accept_app_capabilities example.org/cap/bar/baz
			}`,
			wantCaps: []tailcfg.PeerCapability{
				"example.com/cap/foo",
				"example.org/cap/bar/baz",
			},
		},
		"directive args rejected": {
			input:   "tsid unexpected",
			wantErr: true,
		},
		"unknown subdirective rejected": {
			input:   "tsid {\n\tunknown example.com/cap/foo\n}",
			wantErr: true,
		},
		"empty accept list rejected": {
			input:   "tsid {\n\taccept_app_capabilities\n}",
			wantErr: true,
		},
		"invalid capability rejected": {
			input:   "tsid {\n\taccept_app_capabilities invalid\n}",
			wantErr: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var m Middleware
			err := m.UnmarshalCaddyfile(caddyfile.NewTestDispenser(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("UnmarshalCaddyfile() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}
			if len(m.AcceptAppCaps) != len(tc.wantCaps) {
				t.Fatalf("got %v caps, want %v", m.AcceptAppCaps, tc.wantCaps)
			}
			for i := range tc.wantCaps {
				if m.AcceptAppCaps[i] != tc.wantCaps[i] {
					t.Fatalf("cap %d = %q, want %q", i, m.AcceptAppCaps[i], tc.wantCaps[i])
				}
			}
		})
	}
}

func TestAcceptedAppCapabilitiesJSON(t *testing.T) {
	peerCaps := tailcfg.PeerCapMap{
		"example.com/cap/foo": {
			tailcfg.RawMessage(`{"role":"admin"}`),
			tailcfg.RawMessage(`true`),
		},
		"example.com/cap/bar": {
			tailcfg.RawMessage(`{"role":"viewer"}`),
		},
		"bücher.de/cap/rolle": {
			tailcfg.RawMessage(`{"role":"prüfer"}`),
		},
		"example.com/cap/not-accepted": {
			tailcfg.RawMessage(`{"role":"owner"}`),
		},
	}

	got, err := acceptedAppCapabilitiesJSON(peerCaps, []tailcfg.PeerCapability{
		"example.com/cap/foo",
		"example.com/cap/missing",
		"example.com/cap/bar",
		"bücher.de/cap/rolle",
	})
	if err != nil {
		t.Fatalf("acceptedAppCapabilitiesJSON() error = %v", err)
	}

	decoded, err := new(mime.WordDecoder).DecodeHeader(got)
	if err != nil {
		t.Fatalf("decode output: %v", err)
	}

	var caps map[string][]any
	if err := json.Unmarshal([]byte(decoded), &caps); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}

	if _, ok := caps["example.com/cap/not-accepted"]; ok {
		t.Fatalf("unaccepted capability was included: %s", got)
	}
	if _, ok := caps["example.com/cap/missing"]; ok {
		t.Fatalf("missing capability was included: %s", got)
	}
	if got, want := len(caps["example.com/cap/foo"]), 2; got != want {
		t.Fatalf("foo value count = %d, want %d", got, want)
	}
	if got, want := caps["example.com/cap/foo"][0].(map[string]any)["role"], "admin"; got != want {
		t.Fatalf("foo role = %v, want %v", got, want)
	}
	if got, want := caps["example.com/cap/foo"][1], true; got != want {
		t.Fatalf("foo bool = %v, want %v", got, want)
	}
	if got, want := caps["example.com/cap/bar"][0].(map[string]any)["role"], "viewer"; got != want {
		t.Fatalf("bar role = %v, want %v", got, want)
	}
	if got, want := caps["bücher.de/cap/rolle"][0].(map[string]any)["role"], "prüfer"; got != want {
		t.Fatalf("rolle role = %v, want %v", got, want)
	}
}

func TestAcceptedAppCapabilitiesJSONEmptyObject(t *testing.T) {
	got, err := acceptedAppCapabilitiesJSON(tailcfg.PeerCapMap{}, []tailcfg.PeerCapability{
		"example.com/cap/foo",
	})
	if err != nil {
		t.Fatalf("acceptedAppCapabilitiesJSON() error = %v", err)
	}
	if got != "{}" {
		t.Fatalf("acceptedAppCapabilitiesJSON() = %q, want {}", got)
	}
}
