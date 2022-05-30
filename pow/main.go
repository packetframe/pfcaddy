package packetframe_pow

import (
	"fmt"
	"net/http"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(PoW{})
	httpcaddyfile.RegisterHandlerDirective("packetframe_pow", parseCaddyfile)
}

// PoW represents the Proof of Work module
type PoW struct {
	// Client challenge intensity mode
	Mode string `json:"mode,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (PoW) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.packetframe_pow",
		New: func() caddy.Module { return new(PoW) },
	}
}

// Provision implements caddy.Provisioner
func (p *PoW) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger(p)
	return nil
}

// Validate implements caddy.Validator
func (p *PoW) Validate() error {
	switch p.Mode {
	case "never":
		// "never" disables the module
		return nil
	case "verified":
		// "verified" will only challenge on verified malicious traffic
		return nil
	case "detect":
		// "detect" lets the server decide when to challenge the client
		return nil
	case "always":
		// "always" will always challenge the client
	default:
		return fmt.Errorf("invalid mode: %s", p.Mode)
	}
	return nil
}

func (p PoW) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	p.logger.Info(fmt.Sprintf("got req %s %s", r.Method, r.URL.Path))
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (p *PoW) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new PoW
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p PoW
	for h.Next() {
		if !h.Args(&p.Mode) {
			return nil, h.ArgErr()
		}
	}
	return p, p.UnmarshalCaddyfile(h.Dispenser)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*PoW)(nil)
	_ caddy.Validator             = (*PoW)(nil)
	_ caddyhttp.MiddlewareHandler = (*PoW)(nil)
	_ caddyfile.Unmarshaler       = (*PoW)(nil)
)
