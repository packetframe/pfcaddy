package httpgate

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

//go:embed index.html
var indexSource string

func init() {
	caddy.RegisterModule(HTTPGate{})
	httpcaddyfile.RegisterHandlerDirective("packetframe_httpgate", parseCaddyfile)
}

// HTTPGate represents the HTTP gate module
type HTTPGate struct {
	// Client challenge intensity mode
	Mode string `json:"mode,omitempty"`

	indexTemplate *template.Template
	logger        *zap.Logger
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
	t, err := template.New("").Parse(indexSource)
	if err != nil {
		p.logger.Fatal("failed to parse index template", zap.Error(err))
	}
	p.indexTemplate = t

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

func (p HTTPGate) internalServerError(e error) {
	// TODO: Sentry
	p.logger.Error("internal server error", zap.Error(e))
}

func (p HTTPGate) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	var httpGate string
	c, _ := r.Cookie("pf_httpgate")
	if c != nil {
		httpGate = c.Value
	}

	forceChallenge := false

	if httpGate != "" {
		ok, err := validate(httpGate)
		if err != nil {
			p.internalServerError(err)
			return next.ServeHTTP(w, r) // fail open
		}
		if ok {
			cookie := http.Cookie{
				Name:    "pf_httpgate",
				Value:   httpGate,
				Expires: time.Now().Add(30 * time.Minute),
			}
			http.SetCookie(w, &cookie)
			return next.ServeHTTP(w, r)
		} else { // invalid token
			forceChallenge = true
		}
	}

	if forceChallenge || p.shouldChallenge(r) {
		h, err := newHash()
		if err != nil {
			p.internalServerError(err)
			return next.ServeHTTP(w, r) // fail open
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := p.indexTemplate.Execute(w, map[string]string{"hash": h}); err != nil {
			p.internalServerError(err)
		}
		return nil
	} else { // no challenge
		return next.ServeHTTP(w, r)
	}
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

// shouldChallenge decides if an HTTP request should be challenged;
func (p *HTTPGate) shouldChallenge(r *http.Request) bool {
	// TODO
	return true
}

// Interface guards
var (
	_ caddy.Provisioner           = (*HTTPGate)(nil)
	_ caddy.Validator             = (*HTTPGate)(nil)
	_ caddyhttp.MiddlewareHandler = (*HTTPGate)(nil)
	_ caddyfile.Unmarshaler       = (*HTTPGate)(nil)
)
