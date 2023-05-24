package httpgate

import (
	_ "embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/types"
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
	Mode   string `json:"mode,omitempty"`
	Broker string `json:"broker,omitempty"`
	Rules  string `json:"rules,omitempty"`

	waf           *coraza.WAF
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

	// Setup WAF
	ruleFiles := strings.Split(p.Rules, ",")
	p.logger.Info("Rule files", zap.Strings("files", ruleFiles))
	cfg := coraza.NewWAFConfig()
	for _, f := range ruleFiles {
		cfg = cfg.WithDirectivesFromFile(f)
	}
	waf, err := coraza.NewWAF(cfg)
	if err != nil {
		p.logger.Fatal("failed to setup WAF", zap.Error(err))
	}
	p.waf = &waf

	return nil
}

// Validate implements caddy.Validator
func (p *HTTPGate) Validate() error {
	switch p.Mode {
	case "never":
		// "never" disables the module
		return nil
	case "detect":
		// "detect" lets the server decide when to challenge the client
		return nil
	case "always":
		// "always" will always challenge the client
	default:
		return fmt.Errorf("invalid mode: %s", p.Mode)
	}
	if p.Broker == "" {
		return fmt.Errorf("broker is required")
	}
	return nil
}

func (p HTTPGate) internalServerError(e error) {
	// TODO: Sentry
	p.logger.Error("internal server error", zap.Error(e))
}

func (p HTTPGate) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	debugRequest := r.Header.Get("PF-Debug") == "true"

	var httpGate string
	c, _ := r.Cookie("pf_httpgate")
	if c != nil {
		httpGate = c.Value
	}

	if httpGate != "" {
		ok, err := validate(p.Broker, httpGate)
		if err != nil {
			p.internalServerError(err)
			return next.ServeHTTP(w, r) // fail open
		}
		if ok {
			expiry := time.Now().Add(30 * time.Minute)
			cookie := http.Cookie{
				Name:    "pf_httpgate",
				Value:   httpGate,
				Expires: expiry,
				Path:    "/",
			}
			http.SetCookie(w, &cookie)
			if debugRequest {
				w.Header().Set("PF-Debug-HTTPGate-Expiry", expiry.Format(time.RFC3339))
			}
			return next.ServeHTTP(w, r)
		} else { // invalid token
			// Remove token cookie
			http.SetCookie(w, &http.Cookie{
				Name:    "pf_httpgate",
				Value:   "",
				Expires: time.Unix(0, 0),
				Path:    "/",
			})
		}
	}

	shouldChallenge, matchedRules := p.shouldChallenge(r)
	if debugRequest {
		w.Header().Set("PF-Debug-IsChallenging", ternary(shouldChallenge, "true", "false"))

		var out []string
		for _, rule := range matchedRules {
			if rule.Rule().Severity() == level {
				out = append(out, sanitize(fmt.Sprintf("%d-%s", rule.Rule().ID(), rule.Message())))
			}
		}
		if len(out) > 0 {
			w.Header().Set("PF-Debug-MatchedRules", strings.Join(out, ","))
		}
	}

	if shouldChallenge {
		h, err := newHash(p.Broker)
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
func (p *HTTPGate) UnmarshalCaddyfile(_ *caddyfile.Dispenser) error {
	return nil
}

// parseCaddyfile unmarshalls tokens from h into a new HTTPGate
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var p HTTPGate
	for h.Next() {
		if !h.Args(&p.Broker) {
			return nil, h.ArgErr()
		}
		if !h.Args(&p.Mode) {
			return nil, h.ArgErr()
		}
		if !h.Args(&p.Rules) {
			return nil, h.ArgErr()
		}
	}
	return p, p.UnmarshalCaddyfile(h.Dispenser)
}

// shouldChallenge decides if an HTTP request should be challenged
func (p *HTTPGate) shouldChallenge(r *http.Request) (bool, []types.MatchedRule) {
	if r.Header.Get("PF-ForceChallenge") == "true" {
		return true, nil
	}

	switch p.Mode {
	case "never":
		// "never" disables the module
		return false, nil
	case "detect":
		// "detect" lets the server decide when to challenge the client
		return likelyMalicious(*p.waf, r)
	case "always":
		return true, nil
	default:
		p.internalServerError(fmt.Errorf("code error! invalid mode: %s", p.Mode))
		return true, nil
	}
}

func ternary[T comparable](cond bool, a, b T) T {
	if cond {
		return a
	}
	return b
}

func sanitize(s string) string {
	s = strings.ToUpper(s)
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "_-_", "_")
	var out []rune
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsNumber(r) || r == '-' || r == '_' {
			out = append(out, r)
		}
	}
	return string(out)
}

// Interface guards
var (
	_ caddy.Provisioner           = (*HTTPGate)(nil)
	_ caddy.Validator             = (*HTTPGate)(nil)
	_ caddyhttp.MiddlewareHandler = (*HTTPGate)(nil)
	_ caddyfile.Unmarshaler       = (*HTTPGate)(nil)
)
