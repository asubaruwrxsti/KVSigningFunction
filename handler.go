package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/golang-jwt/jwt/v5"
)

// --- KeyVaultSigner implements crypto.Signer, backed by Key Vault's sign API ---

type KeyVaultSigner struct {
	client  *azkeys.Client
	keyName string
	pub     crypto.PublicKey
}

func (s *KeyVaultSigner) Public() crypto.PublicKey {
	return s.pub
}

func (s *KeyVaultSigner) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	resp, err := s.client.Sign(context.Background(), s.keyName, "", azkeys.SignParameters{
		Algorithm: to(azkeys.SignatureAlgorithmRS256), // match your CA key type
		Value:     digest,
	}, nil)
	if err != nil {
		return nil, fmt.Errorf("keyvault sign: %w", err)
	}
	return resp.Result, nil
}

func to[T any](v T) *T { return &v }

// --- app-level state, initialized once ---

type app struct {
	keyClient    *azkeys.Client
	secretClient *azsecrets.Client
	caKeyName    string
	caCertPEM    []byte // cached CA public cert
	caCert       *x509.Certificate
}

func main() {
	vaultURL := os.Getenv("KEY_VAULT_URL")
	caKeyName := os.Getenv("CA_KEY_NAME")

	cred, err := azidentity.NewDefaultAzureCredential(nil) // uses Function's managed identity in Azure
	if err != nil {
		log.Fatalf("credential: %v", err)
	}

	keyClient, err := azkeys.NewClient(vaultURL, cred, nil)
	if err != nil {
		log.Fatalf("key client: %v", err)
	}
	secretClient, err := azsecrets.NewClient(vaultURL, cred, nil)
	if err != nil {
		log.Fatalf("secret client: %v", err)
	}

	a := &app{
		keyClient:    keyClient,
		secretClient: secretClient,
		caKeyName:    caKeyName,
	}

	if err := a.loadCACert(context.Background()); err != nil {
		log.Fatalf("load CA cert: %v", err)
	}

	http.HandleFunc("/issue", a.handleIssue)
	http.HandleFunc("/api/issue", a.handleIssue)

	port := os.Getenv("FUNCTIONS_CUSTOMHANDLER_PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("listening on :%s", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

func (a *app) loadCACert(ctx context.Context) error {
	// CA public cert stored as a Key Vault secret named "ca-public-cert" (PEM text)
	resp, err := a.secretClient.GetSecret(ctx, "ca-public-cert", "", nil)
	if err != nil {
		return err
	}
	pemBytes := []byte(*resp.Value)
	block, _ := pem.Decode(pemBytes)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	a.caCertPEM = pemBytes
	a.caCert = cert
	return nil
}

func (a *app) handleIssue(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// --- Step 1: validate caller identity (AAD token) ---
	callerID, err := validateCallerToken(r)
	if err != nil {
		http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
		return
	}

	// --- Step 2: parse CSR ---
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	block, _ := pem.Decode(body)
	if block == nil {
		http.Error(w, "invalid PEM", http.StatusBadRequest)
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		http.Error(w, "invalid CSR: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := csr.CheckSignature(); err != nil {
		http.Error(w, "CSR signature invalid", http.StatusBadRequest)
		return
	}

	// --- Step 3: authorize (policy check) ---
	requestedCN := csr.Subject.CommonName
	if !isAllowed(callerID, requestedCN) {
		http.Error(w, "forbidden: subject not permitted for this identity", http.StatusForbidden)
		return
	}

	// --- Step 4: build cert template ---
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		http.Error(w, "serial gen failed", http.StatusInternalServerError)
		return
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: requestedCN},
		DNSNames:              csr.DNSNames, // copy SANs from CSR
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(7 * 24 * time.Hour), // short-lived
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// --- Step 5: get CA key info (need its public part + algorithm) ---
	caKey, err := a.keyClient.GetKey(ctx, a.caKeyName, "", nil)
	if err != nil {
		http.Error(w, "get CA key: "+err.Error(), http.StatusInternalServerError)
		return
	}
	caPub, err := jwkToPublicKey(caKey.Key)
	if err != nil {
		http.Error(w, "parse CA public key: "+err.Error(), http.StatusInternalServerError)
		return
	}

	signer := &KeyVaultSigner{
		client:  a.keyClient,
		keyName: a.caKeyName,
		pub:     caPub,
	}

	// --- Step 6: sign, via Key Vault, through the standard library ---
	certDER, err := x509.CreateCertificate(rand.Reader, template, a.caCert, csr.PublicKey, signer)
	if err != nil {
		http.Error(w, "cert creation failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Write(certPEM)
}

// ==== sishin defined ====
// jwkToPublicKey and validateCallerToken are stubbed above —
// I didn't want to bury two more non-trivial pieces (JWK→crypto.PublicKey conversion, and AAD JWT validation)
// inside an already-long response. I can write both next, fully.

// isAllowed is your policy check — for testing, hardcode a map;
// production version would read from App Config or a small table.

// Signature algorithm (SignatureAlgorithmRS256) needs to match your CA key's type
// — if you generated it as RSA 4096 like in Phase 1, RS256 (or RS384/RS512) is right;
// if you go EC, it'd be ES256 etc.

// The custom handler model means you build this as a normal Go binary (GOOS=linux go build -o handler)
// and the Functions runtime execs it and proxies HTTP to it
// — deployment is a zip with the binary + host.json + function.json, no special Azure Functions Go SDK needed.

var jwksCache = struct {
	mu    sync.RWMutex
	keys  map[string]crypto.PublicKey
	expAt time.Time
}{
	keys: make(map[string]crypto.PublicKey),
}

func isAllowed(callerID, requestedCN string) bool {
	if callerID == "" || requestedCN == "" {
		return false
	}

	policy := strings.TrimSpace(os.Getenv("ALLOWED_CALLER_POLICY"))
	if policy == "" {
		log.Printf("WARNING: ALLOWED_CALLER_POLICY not set; allowing all callers")
		return true
	}

	for _, entry := range strings.Split(policy, ";") {
		parts := strings.SplitN(strings.TrimSpace(entry), "=", 2)
		if len(parts) != 2 {
			continue
		}
		if strings.TrimSpace(parts[0]) != callerID {
			continue
		}
		for _, cn := range strings.Split(parts[1], ",") {
			cn = strings.TrimSpace(cn)
			if cn == "*" || cn == requestedCN {
				return true
			}
		}
		return false
	}

	return false
}

func validateCallerToken(r *http.Request) (string, error) {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if authHeader == "" {
		return "", errors.New("missing Authorization header")
	}

	parts := strings.Fields(authHeader)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", errors.New("expected Authorization: Bearer <token>")
	}

	tokenString := strings.TrimSpace(parts[1])
	if tokenString == "" {
		return "", errors.New("empty bearer token")
	}

	claims := struct {
		jwt.RegisteredClaims
		OID   string `json:"oid"`
		AppID string `json:"appid"`
	}{}

	token, err := jwt.ParseWithClaims(tokenString, &claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Method.Alg())
		}

		kid, _ := token.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("token missing kid header")
		}

		return aadKeyForKID(kid)
	})
	if err != nil || !token.Valid {
		if err == nil {
			err = errors.New("token invalid")
		}
		return "", err
	}

	tenantID := strings.TrimSpace(os.Getenv("TENANT_ID"))
	if tenantID == "" {
		return "", errors.New("TENANT_ID is required for AAD validation")
	}

	validIssuers := []string{
		fmt.Sprintf("https://sts.windows.net/%s/", tenantID),
		fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0", tenantID),
	}
	issuerOK := false
	for _, validIssuer := range validIssuers {
		if claims.Issuer == validIssuer {
			issuerOK = true
			break
		}
	}
	if !issuerOK {
		return "", fmt.Errorf("token issuer %q does not match any expected issuer for tenant %q", claims.Issuer, tenantID)
	}

	expectedAudience := strings.TrimSpace(os.Getenv("EXPECTED_AUDIENCE"))
	if expectedAudience == "" {
		return "", errors.New("EXPECTED_AUDIENCE is required")
	}
	if !containsAudience(claims.Audience, expectedAudience) {
		return "", fmt.Errorf("token audience %v does not contain %q", claims.Audience, expectedAudience)
	}

	callerID := claims.Subject
	if callerID == "" {
		callerID = claims.OID
	}
	if callerID == "" {
		callerID = claims.AppID
	}
	if callerID == "" {
		return "", errors.New("token missing caller identity")
	}

	return callerID, nil
}

func jwkToPublicKey(jwk *azkeys.JSONWebKey) (crypto.PublicKey, error) {
	if jwk == nil {
		return nil, errors.New("nil JWK")
	}
	if jwk.Kty == nil {
		return nil, errors.New("JWK missing key type")
	}
	if *jwk.Kty != azkeys.KeyTypeRSA {
		return nil, fmt.Errorf("unsupported JWK key type %q", *jwk.Kty)
	}
	if len(jwk.N) == 0 || len(jwk.E) == 0 {
		return nil, errors.New("RSA JWK is missing modulus or exponent")
	}

	n := new(big.Int).SetBytes(jwk.N)
	if n.Sign() <= 0 {
		return nil, errors.New("RSA modulus is invalid")
	}

	e := 0
	for _, b := range jwk.E {
		e = (e << 8) | int(b)
	}
	if e <= 0 {
		return nil, errors.New("RSA exponent is invalid")
	}

	return &rsa.PublicKey{N: n, E: e}, nil
}

func aadKeyForKID(kid string) (crypto.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("kid is empty")
	}

	jwkCache := jwksCache
	jwkCache.mu.RLock()
	if key, ok := jwkCache.keys[kid]; ok && time.Now().Before(jwkCache.expAt) {
		jwkCache.mu.RUnlock()
		return key, nil
	}
	jwkCache.mu.RUnlock()

	tenantID := strings.TrimSpace(os.Getenv("TENANT_ID"))
	if tenantID == "" {
		return nil, errors.New("TENANT_ID is required")
	}

	jwksURL := fmt.Sprintf("https://login.microsoftonline.com/%s/discovery/v2.0/keys", tenantID)
	resp, err := http.Get(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("get AAD JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("AAD JWKS returned %s", resp.Status)
	}

	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode AAD JWKS: %w", err)
	}

	cache := make(map[string]crypto.PublicKey, len(jwks.Keys))
	for _, key := range jwks.Keys {
		if key.Kty != "RSA" {
			continue
		}
		decodedN, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			return nil, fmt.Errorf("decode JWK n: %w", err)
		}
		decodedE, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			return nil, fmt.Errorf("decode JWK e: %w", err)
		}
		pub, err := jwkToPublicKey(&azkeys.JSONWebKey{
			Kty: to(azkeys.KeyTypeRSA),
			N:   decodedN,
			E:   decodedE,
		})
		if err != nil {
			return nil, err
		}
		cache[key.Kid] = pub
	}

	jwkCache.mu.Lock()
	jwksCache.keys = cache
	jwksCache.expAt = time.Now().Add(30 * time.Minute)
	jwkCache.mu.Unlock()

	if key, ok := cache[kid]; ok {
		return key, nil
	}

	return nil, fmt.Errorf("kid %q not found in AAD JWKS", kid)
}

func containsAudience(aud jwt.ClaimStrings, expected string) bool {
	for _, a := range aud {
		if a == expected {
			return true
		}
	}
	return false
}
