package httpgate

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
	caddy.RegisterModule(HTTPGate{})
	httpcaddyfile.RegisterHandlerDirective("packetframe_httpgate", parseCaddyfile)
}

// HTTPGate represents the HTTP gate module
type HTTPGate struct {
	// Client challenge intensity mode
	Mode string `json:"mode,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (HTTPGate) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.packetframe_httpgate",
		New: func() caddy.Module { return new(HTTPGate) },
	}
}

// Provision implements caddy.Provisioner
func (p *HTTPGate) Provision(ctx caddy.Context) error {
	p.logger = ctx.Logger(p)
	return nil
}

// Validate implements caddy.Validator
func (p *HTTPGate) Validate() error {
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

func (p HTTPGate) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	p.logger.Info(fmt.Sprintf("got req %s %s", r.Method, r.URL.Path))
	return next.ServeHTTP(w, r)
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler
func (p *HTTPGate) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	return nil
}

// parseCaddyfile unmarshals tokens from h into a new HTTPGate
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p HTTPGate
	for h.Next() {
		if !h.Args(&p.Mode) {
			return nil, h.ArgErr()
		}
	}
	return p, p.UnmarshalCaddyfile(h.Dispenser)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*HTTPGate)(nil)
	_ caddy.Validator             = (*HTTPGate)(nil)
	_ caddyhttp.MiddlewareHandler = (*HTTPGate)(nil)
	_ caddyfile.Unmarshaler       = (*HTTPGate)(nil)
)
