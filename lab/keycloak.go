package main

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// This adapter verifies real Keycloak service access tokens. It is intentionally
// restricted to a workload mapping; it does not fabricate an end-user delegation.
type WorkloadClaims struct {
	AuthorizedParty string `json:"azp"`
	RealmAccess     struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	jwt.RegisteredClaims
}

func verifyKeycloak(raw, realmURL, audience string) (*WorkloadClaims, error) {
	var discovery struct {
		Issuer string `json:"issuer"`
		JWKS   string `json:"jwks_uri"`
	}
	status, err := requestJSON("GET", realmURL+"/.well-known/openid-configuration", nil, "", &discovery)
	if err != nil || status != 200 || discovery.Issuer != realmURL || discovery.JWKS != realmURL+"/protocol/openid-connect/certs" {
		return nil, fmt.Errorf("discovery mismatch")
	}
	c := &WorkloadClaims{}
	token, err := jwt.ParseWithClaims(raw, c, func(t *jwt.Token) (any, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("kid")
		}
		var jwks struct {
			Keys []struct{ Kid, Kty, Alg, Use, N, E string }
		}
		status, e := requestJSON("GET", discovery.JWKS, nil, "", &jwks)
		if e != nil || status != 200 {
			return nil, fmt.Errorf("jwks")
		}
		for _, key := range jwks.Keys {
			if key.Kid == kid && key.Kty == "RSA" && key.Alg == "RS256" && key.Use == "sig" {
				n, e := base64.RawURLEncoding.DecodeString(key.N)
				if e != nil || len(n) < 256 || len(n) > 1024 {
					return nil, fmt.Errorf("rsa modulus")
				}
				ex, e := base64.RawURLEncoding.DecodeString(key.E)
				if e != nil || len(ex) > 4 {
					return nil, fmt.Errorf("rsa exponent")
				}
				v := 0
				for _, b := range ex {
					v = v*256 + int(b)
				}
				if v < 3 || v%2 == 0 {
					return nil, fmt.Errorf("rsa exponent")
				}
				return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: v}, nil
			}
		}
		return nil, fmt.Errorf("kid")
	}, jwt.WithIssuer(realmURL), jwt.WithAudience(audience), jwt.WithValidMethods([]string{"RS256"}), jwt.WithExpirationRequired(), jwt.WithIssuedAt())
	if err != nil || !token.Valid || c.Subject == "" || c.IssuedAt == nil {
		return nil, fmt.Errorf("invalid workload token")
	}
	return c, nil
}
func keycloakProxy(realmURL, business string, a *Authority) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/call" {
			deny(w, 404, "route")
			return
		}
		var op Operation
		if !readJSON(w, r, &op) {
			return
		}
		c, e := verifyKeycloak(bearer(r), realmURL, "tool-proxy")
		if e != nil {
			deny(w, 401, "workload_credential")
			return
		}
		role := false
		for _, v := range c.RealmAccess.Roles {
			if v == "agent-order-reader" {
				role = true
			}
		}
		if c.AuthorizedParty != "agent-tool" || !role {
			deny(w, 403, "workload_mapping")
			return
		}
		if !validOperation(op) || op.Tenant != "acme" || op.Kind != "orders" || op.Action != "read" {
			deny(w, 403, "workload_policy")
			return
		}
		// Local service principal is explicit. It is not Alice and is not token exchange.
		local := claimsFor("svc-reader", "acme", "agent-demo", "business-api", 0, 30*time.Second)
		local.Scope = "orders:read"
		token, e := a.sign(local)
		if e != nil {
			deny(w, 503, "signing")
			return
		}
		var result any
		status, e := requestJSON("POST", business+"/execute", op, token, &result)
		if e != nil {
			deny(w, 503, "business")
			return
		}
		writeJSON(w, status, result)
	})
}
