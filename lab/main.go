// An explicitly limited teaching issuer, proxy and business service.
// This is not an OAuth authorization server or an OpenID Connect provider.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const issuerName = "https://teaching-issuer.invalid/enterprise-agent"
const devAdmin = "public-local-admin-do-not-deploy"
const devProxy = "public-local-proxy-do-not-deploy"
const devApprover = "public-local-approver-do-not-deploy"

type Claims struct {
	Tenant string `json:"tenant"`
	Actor  string `json:"actor"`
	Epoch  int    `json:"epoch"`
	Scope  string `json:"scope"`
	jwt.RegisteredClaims
}
type Person struct {
	Tenant, Password string
	Epoch            int
	Disabled         bool
}
type Authority struct {
	mu     sync.Mutex
	active string
	keys   map[string]ed25519.PrivateKey
	people map[string]*Person
}

func newAuthority() *Authority {
	a := &Authority{keys: map[string]ed25519.PrivateKey{}, people: map[string]*Person{
		"alice":      {Tenant: "acme", Password: "public-alice-pass"},
		"bob":        {Tenant: "beta", Password: "public-bob-pass"},
		"svc-reader": {Tenant: "acme", Password: "public-svc-pass"},
	}}
	a.rotate(false)
	return a
}
func (a *Authority) rotate(retire bool) {
	if retire {
		a.keys = map[string]ed25519.PrivateKey{}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	a.active = fmt.Sprintf("key-%x", sha256.Sum256(priv.Public().(ed25519.PublicKey)))[:20]
	a.keys[a.active] = priv
}
func randomID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func (a *Authority) sign(c Claims) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	t := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
	t.Header["kid"] = a.active
	return t.SignedString(a.keys[a.active])
}
func claimsFor(subject, tenant, actor, aud string, epoch int, ttl time.Duration) Claims {
	now := time.Now()
	return Claims{Tenant: tenant, Actor: actor, Epoch: epoch, Scope: "orders:read orders:refund tickets:close", RegisteredClaims: jwt.RegisteredClaims{
		Issuer: issuerName, Subject: subject, Audience: jwt.ClaimStrings{aud}, ExpiresAt: jwt.NewNumericDate(now.Add(ttl)), IssuedAt: jwt.NewNumericDate(now), NotBefore: jwt.NewNumericDate(now.Add(-time.Second)), ID: randomID()}}
}
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func deny(w http.ResponseWriter, status int, code string) {
	writeJSON(w, status, map[string]string{"error": code})
}
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(v) != nil {
		deny(w, 400, "invalid_json")
		return false
	}
	if d.Decode(&struct{}{}) != io.EOF {
		deny(w, 400, "trailing_json")
		return false
	}
	return true
}
func secret(r *http.Request, s string) bool { return r.Header.Get("Authorization") == "Bearer "+s }
func bearer(r *http.Request) string {
	s := r.Header.Get("Authorization")
	if !strings.HasPrefix(s, "Bearer ") {
		return ""
	}
	return strings.TrimPrefix(s, "Bearer ")
}

var client = &http.Client{Timeout: 2 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

func requestJSON(method, url string, in any, credential string, out any) (int, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return 0, err
	}
	r, err := http.NewRequest(method, url, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	r.Header.Set("Content-Type", "application/json")
	if credential != "" {
		r.Header.Set("Authorization", "Bearer "+credential)
	}
	resp, err := client.Do(r)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if out != nil {
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	} else {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	}
	return resp.StatusCode, err
}

// JWKS is pinned to configuration. Token jku/x5u headers never control a URL.
func verify(raw, audience, authorityURL string) (*Claims, error) {
	if len(raw) > 8192 {
		return nil, fmt.Errorf("oversize token")
	}
	c := &Claims{}
	token, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, fmt.Errorf("kid")
		}
		var keys struct {
			Keys []struct{ Kty, Crv, Kid, X, Alg, Use string }
		}
		status, e := requestJSON("GET", authorityURL+"/jwks", nil, "", &keys)
		if e != nil || status != 200 {
			return nil, fmt.Errorf("jwks unavailable")
		}
		for _, k := range keys.Keys {
			if k.Kid == kid && k.Kty == "OKP" && k.Crv == "Ed25519" && k.Alg == "EdDSA" && k.Use == "sig" {
				b, e := base64.RawURLEncoding.DecodeString(k.X)
				if e != nil || len(b) != ed25519.PublicKeySize {
					return nil, fmt.Errorf("key")
				}
				return ed25519.PublicKey(b), nil
			}
		}
		return nil, fmt.Errorf("unknown kid")
	}, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(issuerName), jwt.WithAudience(audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithLeeway(0))
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid credential")
	}
	if c.Subject == "" || c.Tenant == "" || c.ID == "" || c.IssuedAt == nil || c.NotBefore == nil || c.ExpiresAt.Time.Sub(c.IssuedAt.Time) > 2*time.Minute {
		return nil, fmt.Errorf("incomplete credential")
	}
	if len(c.Audience) != 1 {
		return nil, fmt.Errorf("multiple audiences")
	}
	return c, nil
}

// Online state check gives this lab immediate revocation at the check boundary.
func live(c *Claims, url string) bool {
	var state struct {
		Active bool
		Tenant string
		Epoch  int
	}
	status, err := requestJSON("POST", url+"/state", map[string]string{"subject": c.Subject}, devProxy, &state)
	return err == nil && status == 200 && state.Active && state.Tenant == c.Tenant && state.Epoch == c.Epoch
}
func (a *Authority) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		defer a.mu.Unlock()
		keys := []map[string]string{}
		for kid, k := range a.keys {
			keys = append(keys, map[string]string{"kty": "OKP", "crv": "Ed25519", "kid": kid, "alg": "EdDSA", "use": "sig", "x": base64.RawURLEncoding.EncodeToString(k.Public().(ed25519.PublicKey))})
		}
		writeJSON(w, 200, map[string]any{"keys": keys})
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Subject, Password string }
		if !readJSON(w, r, &in) {
			return
		}
		a.mu.Lock()
		p, ok := a.people[in.Subject]
		if !ok || p.Disabled || p.Password != in.Password {
			a.mu.Unlock()
			deny(w, 401, "login_failed")
			return
		}
		tenant, epoch := p.Tenant, p.Epoch
		a.mu.Unlock()
		token, err := a.sign(claimsFor(in.Subject, tenant, "", "tool-proxy", epoch, 90*time.Second))
		if err != nil {
			deny(w, 500, "signing")
			return
		}
		writeJSON(w, 200, map[string]string{"access_token": token, "token_type": "Bearer"})
	})
	mux.HandleFunc("POST /state", func(w http.ResponseWriter, r *http.Request) {
		if !secret(r, devProxy) {
			deny(w, 401, "service_identity")
			return
		}
		var in struct{ Subject string }
		if !readJSON(w, r, &in) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		p, ok := a.people[in.Subject]
		if !ok {
			deny(w, 404, "subject")
			return
		}
		writeJSON(w, 200, map[string]any{"Active": !p.Disabled, "Tenant": p.Tenant, "Epoch": p.Epoch})
	})
	mux.HandleFunc("POST /admin/revoke", func(w http.ResponseWriter, r *http.Request) {
		if !secret(r, devAdmin) {
			deny(w, 401, "admin")
			return
		}
		var in struct{ Subject string }
		if !readJSON(w, r, &in) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		p, ok := a.people[in.Subject]
		if !ok {
			deny(w, 404, "subject")
			return
		}
		p.Epoch++
		writeJSON(w, 200, map[string]any{"epoch": p.Epoch})
	})
	mux.HandleFunc("POST /admin/rotate", func(w http.ResponseWriter, r *http.Request) {
		if !secret(r, devAdmin) {
			deny(w, 401, "admin")
			return
		}
		var in struct{ Retire bool }
		if !readJSON(w, r, &in) {
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		a.rotate(in.Retire)
		writeJSON(w, 200, map[string]string{"active": a.active})
	})
	return mux
}

// attachDelegation implements a proprietary laboratory credential narrowing endpoint.
func attachDelegation(a *Authority, base http.Handler, authorityURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/delegate" {
			base.ServeHTTP(w, r)
			return
		}
		if r.Method != "POST" {
			deny(w, 405, "method")
			return
		}
		if !secret(r, devProxy) {
			deny(w, 401, "service_identity")
			return
		}
		var in struct{ Token string }
		if !readJSON(w, r, &in) {
			return
		}
		c, err := verify(in.Token, "tool-proxy", authorityURL)
		if err != nil || c.Actor != "" || !live(c, authorityURL) {
			deny(w, 401, "delegation_denied")
			return
		}
		narrowed := claimsFor(c.Subject, c.Tenant, "agent-demo", "business-api", c.Epoch, 30*time.Second)
		narrowed.Scope = c.Scope
		if narrowed.ExpiresAt.After(c.ExpiresAt.Time) {
			narrowed.ExpiresAt = c.ExpiresAt
		}
		token, err := a.sign(narrowed)
		if err != nil {
			deny(w, 500, "signing")
			return
		}
		writeJSON(w, 200, map[string]string{"access_token": token})
	})
}

type Operation struct {
	Tenant   string `json:"tenant"`
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Action   string `json:"action"`
	Amount   int    `json:"amount"`
	Note     string `json:"note"`
	Approval string `json:"approval,omitempty"`
}
type Object struct {
	Tenant, Kind, ID, Status string
	Refund                   int
}
type Approval struct {
	Hash, Subject, Actor, Tenant string
	Epoch                        int
	Expires                      time.Time
	Used                         bool
}
type Audit struct {
	RequestID   string `json:"request_id"`
	Subject     string `json:"subject"`
	Actor       string `json:"actor"`
	Tenant      string `json:"tenant"`
	Object      string `json:"object"`
	Action      string `json:"action"`
	Decision    string `json:"decision"`
	Reason      string `json:"reason"`
	ApprovalRef string `json:"approval_ref,omitempty"`
}
type Business struct {
	actors    map[string]bool // Immutable allowlist configured before serving.
	mu        sync.Mutex
	objects   map[string]*Object
	approvals map[string]*Approval
	audit     []Audit
	authority string
}

func newBusiness(authority string) *Business {
	return &Business{authority: authority, actors: map[string]bool{"agent-demo": true}, objects: map[string]*Object{
		"acme/orders/o-100":  {Tenant: "acme", Kind: "orders", ID: "o-100", Status: "paid"},
		"beta/orders/o-200":  {Tenant: "beta", Kind: "orders", ID: "o-200", Status: "paid"},
		"acme/tickets/t-100": {Tenant: "acme", Kind: "tickets", ID: "t-100", Status: "open"},
		"beta/tickets/t-200": {Tenant: "beta", Kind: "tickets", ID: "t-200", Status: "open"}}, approvals: map[string]*Approval{}}
}
func digest(op Operation) string {
	op.Approval = ""
	b, _ := json.Marshal(op)
	v := sha256.Sum256(b)
	return hex.EncodeToString(v[:])
}
func validOperation(op Operation) bool {
	if len(op.ID) > 80 || len(op.Tenant) > 80 || len(op.Note) > 512 || strings.ContainsAny(op.ID+op.Tenant, "/\\\r\n") || op.ID == "" || op.Tenant == "" {
		return false
	}
	return (op.Kind == "orders" && ((op.Action == "read" && op.Amount == 0) || (op.Action == "refund" && op.Amount > 0 && op.Amount <= 10000))) || (op.Kind == "tickets" && op.Action == "close" && op.Amount == 0)
}
func allowedScope(c *Claims, op Operation) bool {
	want := op.Kind + ":" + op.Action
	for _, s := range strings.Fields(c.Scope) {
		if s == want {
			return true
		}
	}
	return false
}
func (b *Business) authorize(raw string, op Operation) (*Claims, string) {
	c, e := verify(raw, "business-api", b.authority)
	if e != nil {
		return nil, "credential"
	}
	if !live(c, b.authority) {
		return c, "revoked_or_unavailable"
	}
	if !b.actors[c.Actor] {
		return c, "actor"
	}
	if !validOperation(op) {
		return c, "schema"
	}
	if c.Tenant != op.Tenant {
		return c, "tenant"
	}
	if !allowedScope(c, op) {
		return c, "scope"
	}
	return c, ""
}
func (b *Business) record(c *Claims, op Operation, decision, reason string) {
	a := Audit{RequestID: randomID(), Action: op.Action, Decision: decision, Reason: reason}
	// Only resolved server-owned object identifiers enter the audit verbatim.
	// Unknown/rejected identifiers may contain secrets or personal text.
	key := op.Tenant + "/" + op.Kind + "/" + op.ID
	if _, ok := b.objects[key]; ok && validOperation(op) {
		a.Object = op.Kind + "/" + op.ID
	} else {
		sum := sha256.Sum256([]byte(key))
		a.Object = "unresolved:" + hex.EncodeToString(sum[:8])
	}
	if op.Action != "read" && op.Action != "refund" && op.Action != "close" {
		a.Action = "invalid"
	}
	if c != nil {
		a.Subject = c.Subject
		a.Actor = c.Actor
		a.Tenant = c.Tenant
	}
	if op.Approval != "" {
		v := sha256.Sum256([]byte(op.Approval))
		a.ApprovalRef = hex.EncodeToString(v[:8])
	}
	b.audit = append(b.audit, a)
}
func (b *Business) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /approve", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Approver-Key") != devApprover {
			deny(w, 401, "approver")
			return
		}
		var op Operation
		if !readJSON(w, r, &op) {
			return
		}
		c, why := b.authorize(bearer(r), op)
		b.mu.Lock()
		defer b.mu.Unlock()
		if why != "" {
			b.record(c, op, "deny", why)
			deny(w, 403, why)
			return
		}
		if op.Action == "read" {
			deny(w, 400, "approval_not_required")
			return
		}
		key := op.Tenant + "/" + op.Kind + "/" + op.ID
		if _, ok := b.objects[key]; !ok {
			deny(w, 404, "object")
			return
		}
		id := randomID()
		b.approvals[id] = &Approval{Hash: digest(op), Subject: c.Subject, Actor: c.Actor, Tenant: c.Tenant, Epoch: c.Epoch, Expires: time.Now().Add(45 * time.Second)}
		b.record(c, op, "allow", "approved")
		writeJSON(w, 200, map[string]string{"approval": id})
	})
	mux.HandleFunc("POST /execute", func(w http.ResponseWriter, r *http.Request) {
		var op Operation
		if !readJSON(w, r, &op) {
			return
		}
		c, why := b.authorize(bearer(r), op)
		b.mu.Lock()
		defer b.mu.Unlock()
		if why != "" {
			b.record(c, op, "deny", why)
			deny(w, 403, why)
			return
		}
		key := op.Tenant + "/" + op.Kind + "/" + op.ID
		obj, ok := b.objects[key]
		if !ok {
			b.record(c, op, "deny", "object")
			deny(w, 404, "object")
			return
		}
		if op.Action != "read" {
			a, ok := b.approvals[op.Approval]
			if !ok || a.Used || time.Now().After(a.Expires) || a.Hash != digest(op) || a.Subject != c.Subject || a.Actor != c.Actor || a.Tenant != c.Tenant || a.Epoch != c.Epoch {
				b.record(c, op, "deny", "approval_binding")
				deny(w, 403, "approval_binding")
				return
			}
			if (op.Action == "refund" && obj.Status != "paid") || (op.Action == "close" && obj.Status != "open") {
				b.record(c, op, "deny", "state_conflict")
				deny(w, 409, "state_conflict")
				return
			}
			// One mutex emulates one database transaction: compare + consume + mutate + audit.
			a.Used = true
			if op.Action == "refund" {
				obj.Refund = op.Amount
				obj.Status = "refunded"
			} else {
				obj.Status = "closed"
			}
		}
		b.record(c, op, "allow", "executed")
		writeJSON(w, 200, obj)
	})
	mux.HandleFunc("GET /audit", func(w http.ResponseWriter, r *http.Request) {
		if !secret(r, devAdmin) {
			deny(w, 401, "admin")
			return
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		writeJSON(w, 200, b.audit)
	})
	return mux
}
func proxy(authority, business string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /call", func(w http.ResponseWriter, r *http.Request) {
		var op Operation
		if !readJSON(w, r, &op) {
			return
		}
		c, err := verify(bearer(r), "tool-proxy", authority)
		if err != nil || c.Actor != "" || !live(c, authority) {
			deny(w, 401, "credential")
			return
		}
		if !validOperation(op) || op.Tenant != c.Tenant || !allowedScope(c, op) {
			deny(w, 403, "policy")
			return
		}
		var token struct {
			AccessToken string `json:"access_token"`
		}
		status, err := requestJSON("POST", authority+"/delegate", map[string]string{"Token": bearer(r)}, devProxy, &token)
		if err != nil || status != 200 {
			deny(w, 503, "delegation_unavailable")
			return
		}
		var result any
		status, err = requestJSON("POST", business+"/execute", op, token.AccessToken, &result)
		if err != nil {
			deny(w, 503, "business_unavailable")
			return
		}
		writeJSON(w, status, result)
	})
	return mux
}
func serve(addr string, h http.Handler) {
	s := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 16384}
	log.Fatal(s.ListenAndServe())
}
func main() {
	// Public credentials require every listener and target to stay on loopback.
	for _, addr := range []string{"127.0.0.1:9101", "127.0.0.1:9102", "127.0.0.1:9103"} {
		host, _, _ := net.SplitHostPort(addr)
		if !net.ParseIP(host).IsLoopback() {
			os.Exit(2)
		}
	}
	a := newAuthority()
	url := "http://127.0.0.1:9101"
	b := newBusiness(url)
	go serve("127.0.0.1:9101", attachDelegation(a, a.handler(), url))
	go serve("127.0.0.1:9103", b.handler())
	log.Print("Teaching lab only: issuer 9101, proxy 9102, business 9103; all state in memory")
	serve("127.0.0.1:9102", proxy(url, "http://127.0.0.1:9103"))
}
