package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func keycloakToken(t *testing.T, realm, clientID string) string {
	t.Helper()
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {clientID}, "client_secret": {"public-keycloak-dev-secret"}}
	resp, e := http.PostForm(realm+"/protocol/openid-connect/token", form)
	if e != nil {
		t.Fatal(e)
	}
	defer resp.Body.Close()
	var out struct {
		Token string `json:"access_token"`
	}
	data, _ := io.ReadAll(resp.Body)
	if json.Unmarshal(data, &out) != nil || resp.StatusCode != 200 || out.Token == "" {
		t.Fatalf("keycloak token %d %s", resp.StatusCode, data)
	}
	return out.Token
}
func TestRealKeycloakWorkload(t *testing.T) {
	realm := os.Getenv("KEYCLOAK_REALM_URL")
	if realm == "" {
		t.Skip("requires the real Keycloak CI container; no substitute issuer is used")
	}
	f := setup(t)
	p := httptest.NewServer(keycloakProxy(realm, f.api.URL, f.a))
	defer p.Close()
	token := keycloakToken(t, realm, "agent-tool")
	claims, e := verifyKeycloak(token, realm, "tool-proxy")
	if e != nil {
		t.Fatal(e)
	}
	t.Log("real discovery/JWKS verified issuer", claims.Issuer, "audience", claims.Audience, "service subject", claims.Subject, "expires", claims.ExpiresAt.Time.UTC())
	if _, e = verifyKeycloak(token, realm, "wrong-audience"); e == nil {
		t.Fatal("wrong audience accepted")
	}
	if _, e = verifyKeycloak(token, strings.Replace(realm, "/book", "/wrong", 1), "tool-proxy"); e == nil {
		t.Fatal("wrong issuer accepted")
	}
	code, _ := call(t, p.URL+"/call", token, readOp())
	expect(t, code, 200)
	op := readOp()
	op.Tenant = "beta"
	op.ID = "o-200"
	code, _ = call(t, p.URL+"/call", token, op)
	expect(t, code, 403)
	code, _ = call(t, p.URL+"/call", token, refundOp())
	expect(t, code, 403)
	untrusted := keycloakToken(t, realm, "untrusted-tool")
	code, _ = call(t, p.URL+"/call", untrusted, readOp())
	expect(t, code, 403)
	remaining := time.Until(claims.ExpiresAt.Time) + time.Second
	if remaining > 25*time.Second {
		t.Fatalf("lab accessTokenLifespan must be 12s, got %v", remaining)
	}
	time.Sleep(remaining)
	code, _ = call(t, p.URL+"/call", token, readOp())
	expect(t, code, 401)
	fresh := keycloakToken(t, realm, "agent-tool")
	code, _ = call(t, p.URL+"/call", fresh, readOp())
	expect(t, code, 200)
}
