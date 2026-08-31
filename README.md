# mTLS Client Certificate Issuance — Architecture & Setup Documentation

## 1. Problem Statement

The original process for issuing mTLS client certificates (used by a Caddy reverse proxy configured for mTLS) was manual:

- The root CA was downloaded locally on demand.
- Client certificates were signed by hand using the local copy of the CA private key.
- This was tedious and, more importantly, insecure — the CA private key was repeatedly exposed on a local machine instead of staying in a single, access-controlled location.

**Goal:** automate client certificate issuance through an Azure Function, backed by an Azure Key Vault-held CA key, callable securely by client applications (Azure App Services) at startup.

---

## 2. Key Concepts

### 2.1 CSR-based issuance (not key generation by the signer)
The client application — not the signing service — generates its own private/public keypair locally and sends only a **Certificate Signing Request (CSR)** (public key + identity info) to the issuing service. The private key never leaves the client. This is the same model used by ACME (Let's Encrypt), HashiCorp Vault PKI, and step-ca.

Rejected alternative: the signing Function generates the keypair and returns both key and cert. This was the original design and was walked back — it means the private key transits the network and briefly exists in the Function's memory/logs, which undermines the entire point of centralizing trust in Key Vault.

### 2.2 Remote signing via Key Vault, never exporting the CA private key
The CA private key is stored in Azure Key Vault as a **Key** object with `sign`-only permissions granted to the issuing Function's managed identity. The Function never calls `get`/export on the key — it sends a hash to Key Vault's `sign` API and gets back a signature. The CA private key never exists outside Key Vault's boundary (HSM-backed on Premium tier).

### 2.3 `crypto.Signer` — why the issuing service is written in Go
Go's standard library `crypto/x509.CreateCertificate()` accepts any type implementing the `crypto.Signer` interface (`Public()` + `Sign()`), so a small adapter wrapping Key Vault's `sign` API plugs directly into normal certificate-building code. This is a first-class capability in Go (and .NET, via `X509SignatureGenerator`) but **not** natively supported in Python or Node.js, where `cryptography`/`node-forge` assume a local private key object and require manual TBSCertificate/ASN.1 assembly to work around it. Go was chosen specifically to avoid that manual DER-assembly work.

### 2.4 Identity-based authentication, not shared secrets
Client App Services authenticate to the issuing Function using their own **system-assigned Managed Identity**, requesting an Azure AD (Entra ID) token scoped to the Function's audience. The Function validates the token (signature, issuer, audience) and extracts the caller's identity (`oid`/`sub`) from the token claims — no API keys or shared secrets exist anywhere in the flow.

### 2.5 Authorization is separate from authentication
Proving *who* is calling is not sufficient — the Function also checks *what* that caller is allowed to request (i.e., which Common Name/subject it may claim), via a policy check (`isAllowed(callerID, requestedCN)`). This prevents one authenticated app from requesting a certificate impersonating another app's identity.

---

## 3. Alternatives Considered

| Option | Description | Verdict |
|---|---|---|
| **Function generates key + cert, returns both** | Simplest to build; matches original manual process | Rejected — private key exposure in transit/memory |
| **Client apps read certs directly from Key Vault** | Store issued cert as a KV secret, client app identity granted `get` | Rejected — doesn't scale (per-app KV RBAC grants), KV isn't designed as a general per-tenant artifact store, doesn't remove the authentication problem, just relocates it to a coarser IAM surface |
| **CSR submitted to Function, Function signs via Key Vault `sign`, returns cert synchronously** | Client generates keypair locally, private key never transmitted | **Selected** — matches industry-standard PKI patterns (ACME, Vault PKI, step-ca) |
| **Portal-triggered manual issuance (function generates key+cert, admin downloads via Portal)** | Fast to stand up for a small trusted team | Considered acceptable as a low-volume/admin-only fallback, but reintroduces private-key handling and relies on coarse Azure RBAC (Contributor-level) rather than cert-specific authorization |
| **Reuse an existing full PKI product (HashiCorp Vault PKI engine, smallstep step-ca)** | Purpose-built, handles CSR signing, revocation, CRL/OCSP, leasing, audit out of the box | Not adopted for this prototype (kept in Azure-native tooling), but flagged as the more robust long-term option if requirements grow (revocation, short-lived cert renewal automation, etc.) |
| **Language for the signing service: Python vs. Go vs. .NET** | Python's `cryptography` library has no native remote-signer abstraction (manual TBS-bytes + hash + external sign + DER reassembly required); .NET and Go both have first-class support (`X509SignatureGenerator`, `crypto.Signer`) | **Go selected** — user was comfortable in Go, and it avoids the manual ASN.1 work Python would require |

---

## 4. Architecture Overview

```
Client App Service (managed identity)
   |
   | 1. genkey locally (private key never leaves the app)
   | 2. build CSR (public key + requested CN/SANs)
   | 3. request AAD token scoped to signing Function's audience
   | 4. POST CSR + Bearer token -> /api/issue
   v
Azure Function (Go, custom handler, containerized)
   |
   | 5. validate AAD token (signature via tenant JWKS, issuer, audience)
   | 6. parse + validate CSR signature
   | 7. authorize: does caller identity match a policy-allowed subject?
   | 8. build X.509 template (short validity, clientAuth EKU, SANs from CSR)
   | 9. call Key Vault "sign" on the CA key (CA private key never leaves KV)
   | 10. assemble signed certificate, return synchronously
   v
Client App Service
   | 11. writes signed cert + its own local private key to disk
   | 12. loads both for outbound mTLS to Caddy reverse proxy
```

### Trust chain
```
Root CA (in Key Vault, sign-only permission for the Function's identity)
   -> signs -> Client certificate (short-lived, clientAuth EKU, CN = app identity)
Caddy trusts the Root CA's public certificate for mTLS validation.
```

---

## 5. Requirements

### 5.1 Azure resources
- **Azure Key Vault** (RBAC authorization mode) — holds the CA signing key.
- **Azure Container Registry (ACR)** — hosts the Function's container image.
- **Azure Function App** — Linux, container-based (Premium or Dedicated plan; **not** Flex Consumption, which does not support `az functionapp config container set`).
- **Storage Account** — required by all Function Apps regardless of hosting model.
- **App Service(s)** — the client applications requesting certificates.
- **Azure AD (Entra ID) App Registration** — defines the audience the signing Function validates tokens against.

### 5.2 Identities and role assignments
| Identity | Role | Scope |
|---|---|---|
| Signing Function's managed identity | `AcrPull` | Container Registry |
| Signing Function's managed identity | `Key Vault Crypto User` (sign-only) | Key Vault |
| Signing Function's managed identity | `Key Vault Secrets User` (read CA public cert) | Key Vault |
| Client App Service's managed identity | Custom/no elevated role required — only needs to request a token for the Function's audience | — |
| Human operator (bootstrap/testing) | `Key Vault Administrator` or `Key Vault Crypto Officer` | Key Vault (for initial CA key/cert creation only) |

### 5.3 Tooling
- Go 1.22+ (signing Function)
- Docker (image build; must target `linux/amd64` explicitly when building from Apple Silicon)
- Azure CLI (`az`)
- OpenSSL (client-side CSR generation, verification)

---

## 6. Implementation Details

### 6.1 Signing Function — core logic (`handler.go`)
- `KeyVaultSigner` struct implements `crypto.Signer`, wrapping `azkeys.Client.Sign()`.
- `handleIssue`:
  1. `validateCallerToken` — parses Bearer JWT, verifies signature against tenant-scoped JWKS (`https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys` — **never** the `common` endpoint, which would accept tokens from any Entra ID tenant), checks `iss` against known-good issuer formats (both v1: `https://sts.windows.net/{tenant}/` and v2: `https://login.microsoftonline.com/{tenant}/v2.0`, since AAD tokens vary in version depending on how they were requested), and checks `aud` against `EXPECTED_AUDIENCE`.
  2. Parses and validates the CSR's self-signature.
  3. `isAllowed(callerID, requestedCN)` — policy check against an allowlist (`ALLOWED_CALLER_POLICY` env var; production should back this with a real config/database).
  4. Builds an `x509.Certificate` template: short validity (7 days in the prototype), `KeyUsageDigitalSignature`, `ExtKeyUsageClientAuth`, SANs copied from the CSR, `BasicConstraintsValid: true` (`CA:FALSE`).
  5. Calls `x509.CreateCertificate()` with the `KeyVaultSigner`, which triggers the remote `sign` call to Key Vault.
  6. Returns the PEM-encoded signed certificate.

**Both `validateCallerToken` and `isAllowed` fail open if misconfigured** unless explicitly hardened:
- Missing `EXPECTED_AUDIENCE` → now fails closed (returns 401) after correction.
- Missing `ALLOWED_CALLER_POLICY` → currently **defaults to permit all callers** (acceptable only for dev/test; must be replaced before production use).

### 6.2 Deployment model
- Deployed as a **custom handler** container (not zip deploy) since the Function App runs on a Container Registry-backed image.
- Base image issue encountered: `mcr.microsoft.com/azure-functions/dotnet:4-appservice` (initially used) does not support `linux/amd64` platform builds reliably from Apple Silicon and is semantically the wrong image for a non-.NET custom handler. No single confirmed "generic custom handler" tag exists at the time of writing — this needs to be resolved per Microsoft's current published image list before production hardening (was in progress at time of writing; not fully resolved).
- All builds must be run with `--platform linux/amd64` explicitly when building on Apple Silicon hardware, since the Function App plan runs amd64.
- Route note: the Functions host forwards the **full path** (e.g. `/api/issue`, matching the route defined in `function.json`) to the custom handler process — the Go router must register at that full path, not just the route's suffix.

### 6.3 CA certificate bootstrap — resolved

Two approaches were evaluated for creating the self-signed root CA certificate itself:

1. **`az keyvault certificate create`** (CLI-native): generates a key + self-signed cert together inside Key Vault. **Confirmed broken for this use case** — Azure Key Vault's certificate creation always produces `Basic Constraints: CA:FALSE`, regardless of policy JSON input, because the CLI/SDK layer does not expose a way to set `CA:TRUE`. This is a documented, known Azure limitation (tracked in public Azure CLI/REST API spec GitHub issues), not a configuration error. A cert with `CA:FALSE` cannot validly sign other certificates and will fail `openssl verify` with error 79 (`invalid CA certificate`).

2. **Direct `az rest` call to the Key Vault REST API** with an undocumented `basic_constraints: { "ca": true }` field inside `x509_props`. **Confirmed working.** Two schema details had to be corrected before it succeeded:
   - REST API `7.4` uses **snake_case** field names (`key_props`, `secret_props`, `x509_props`), not the camelCase used in some older blog examples (`keyProperties`, `x509CertificateProperties`). Using the wrong casing causes the API to silently ignore the whole block, which surfaces as a confusing `"Either subjectName or san must be present"` error even though a subject was supplied.
   - `basic_constraints` is not in Microsoft's officially documented schema, but is honored by the backend when nested correctly inside `x509_props` alongside the other snake_case fields.

   The resulting certificate was verified to have `X509v3 Basic Constraints: critical / CA:TRUE`, and downstream client certificates issued against it passed `openssl verify -CAfile ca-cert.pem client.crt` with `OK`. See §7.2 for the exact working request body.

3. **Fallback (not needed, but documented for reference): a one-off local Go script**, using the exact same `KeyVaultSigner`/`crypto.Signer` pattern as the Function itself, calling `x509.CreateCertificate()` locally with `IsCA: true` and `BasicConstraintsValid: true`, signing against the *existing* Key Vault-held key. This remains the fallback if the undocumented REST field is ever changed/removed by Microsoft, since it relies on documented, stable Go standard library behavior instead.

**Resolution:** Option 2 (`az rest` with corrected snake_case `basic_constraints`) is the method actually used going forward. The final CA certificate object is named `ca-root-cert` (superseding the earlier, broken `ca-signing-cert` created via the CLI-native path).

---

## 7. Step-by-Step Setup (as executed)

### 7.1 Create the CA signing key in Key Vault
```bash
az keyvault key create \
  --vault-name PivotKV \
  --name ca-signing-key \
  --kty RSA \
  --size 4096 \
  --ops sign
```
Requires `Key Vault Administrator` or `Key Vault Crypto Officer` role on the vault for the operator running this (RBAC-mode vaults reject this otherwise with `ForbiddenByRbac`).

### 7.2 Create the self-signed root CA certificate

Write the certificate policy with the corrected snake_case schema, including the undocumented `basic_constraints` field (see §6.3):

```bash
cat > ca-policy.json << 'EOF'
{
  "policy": {
    "key_props": {
      "exportable": false,
      "kty": "RSA",
      "key_size": 4096,
      "reuse_key": false
    },
    "secret_props": {
      "contentType": "application/x-pem-file"
    },
    "x509_props": {
      "subject": "CN=MyOrg Root CA",
      "key_usage": [
        "keyCertSign",
        "cRLSign"
      ],
      "basic_constraints": {
        "ca": true
      },
      "validity_months": 120
    },
    "issuer": {
      "name": "Self"
    }
  }
}
EOF
```

Call the Key Vault REST API directly via `az rest` (the `az keyvault certificate create` CLI wrapper does not pass `basic_constraints` through — see §6.3):

```bash
az rest \
  --method post \
  --url "https://pivotkv.vault.azure.net/certificates/ca-root-cert/create?api-version=7.4" \
  --headers "Content-Type=application/json" \
  --body @ca-policy.json \
  --resource "https://vault.azure.net"
```

Confirm creation and download the public certificate:

```bash
az keyvault certificate show --vault-name PivotKV --name ca-root-cert --query "{id:id, x5t:x5t}"

az keyvault certificate download \
  --vault-name PivotKV \
  --name ca-root-cert \
  --file ca-cert.pem \
  --encoding PEM
```

Verify the fix actually took effect:

```bash
openssl x509 -in ca-cert.pem -noout -text | grep -A2 "Basic Constraints"
# Expect: X509v3 Basic Constraints: critical / CA:TRUE
```

### 7.3 Store the CA public certificate as a Key Vault secret
```bash
az keyvault secret set \
  --vault-name PivotKV \
  --name ca-public-cert \
  --file ca-cert.pem
```

### 7.4 Build and push the signing Function's container image
```bash
docker build --platform linux/amd64 \
  -t containerrestry-cgdqe7hee4hxe3ht.azurecr.io/signing-function:latest .
docker push containerrestry-cgdqe7hee4hxe3ht.azurecr.io/signing-function:latest
```

### 7.5 Create supporting infrastructure (Storage Account, Linux App Service Plan)
```bash
az storage account create \
  --name rgprototype96e5 \
  --resource-group rg-prototype \
  --location italynorth \
  --sku Standard_LRS

az functionapp plan create \
  --name signing-function-plan \
  --resource-group rg-prototype \
  --location italynorth \
  --sku B1 \
  --is-linux
```

### 7.6 Create the Function App from the container image
```bash
az functionapp create \
  --name GeneratemTLSv2 \
  --resource-group rg-prototype \
  --plan signing-function-plan \
  --storage-account rgprototype96e5 \
  --image containerrestry-cgdqe7hee4hxe3ht.azurecr.io/signing-function:latest \
  --functions-version 4
```

### 7.7 Assign the Function's managed identity and grant permissions
```bash
az functionapp identity assign --name GeneratemTLSv2 --resource-group rg-prototype

principalId=$(az functionapp identity show --name GeneratemTLSv2 --resource-group rg-prototype --query principalId -o tsv)

az role assignment create \
  --assignee-object-id $principalId \
  --assignee-principal-type ServicePrincipal \
  --role AcrPull \
  --scope $(az acr show --name ContainerRestry --query id -o tsv)

az functionapp config set \
  --name GeneratemTLSv2 \
  --resource-group rg-prototype \
  --generic-configurations '{"acrUseManagedIdentityCreds": true}'

az role assignment create \
  --assignee $principalId \
  --role "Key Vault Crypto User" \
  --scope $(az keyvault show --name PivotKV --query id -o tsv)

az role assignment create \
  --assignee $principalId \
  --role "Key Vault Secrets User" \
  --scope $(az keyvault show --name PivotKV --query id -o tsv)
```
**Note:** use `--assignee-object-id` + `--assignee-principal-type ServicePrincipal` rather than plain `--assignee` — name-resolution via Azure AD Graph can lag right after identity creation and produce misleading results in `az role assignment list` (a display-name artifact was observed during setup, resolved by querying raw `principalId` values instead of the friendly-name table view).

### 7.8 Configure application settings
```bash
az functionapp config appsettings set \
  --name GeneratemTLSv2 \
  --resource-group rg-prototype \
  --settings \
    KEY_VAULT_URL="https://pivotkv.vault.azure.net/" \
    CA_KEY_NAME="ca-root-cert" \
    TENANT_ID="<tenant-id>" \
    EXPECTED_AUDIENCE="<app registration audience>"
```
Note: `CA_KEY_NAME` was initially set to `ca-signing-key` (the standalone key object from §7.1) and briefly to `ca-signing-cert` (the broken CLI-native certificate from the earlier, rejected approach in §6.3) during iteration. The final, correct value is `ca-root-cert` — the certificate object created via the working `az rest` method in §7.2.

### 7.9 Restart and verify
```bash
az functionapp restart --name GeneratemTLSv2 --resource-group rg-prototype
az webapp log tail --name GeneratemTLSv2 --resource-group rg-prototype
```
Confirms the container pulled successfully, the Go process bound to the assigned port, and `loadCACert()` successfully read the CA public cert secret.

### 7.10 Client-side test (manual CSR, standing in for the App Service flow)
```bash
openssl req -new -newkey rsa:2048 -nodes \
  -keyout client.key \
  -out client.csr \
  -subj "/CN=example-client"

TOKEN=$(az account get-access-token --resource <expected-audience> --query accessToken -o tsv)

curl -i -X POST \
  "https://generatemtlsv2.azurewebsites.net/api/issue" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @client.csr -o client.crt
```

### 7.11 Verify the issued certificate
```bash
openssl x509 -in client.crt -noout -text
openssl verify -CAfile ca-cert.pem client.crt
```
Confirmed working: correct issuer/subject, 7-day validity, `Digital Signature` key usage, `TLS Web Client Authentication` EKU, `CA:FALSE`, and chain validation returning `client.crt: OK` against the corrected, properly-flagged `CA:TRUE` root cert (§7.2).

### 7.12 Clean, from-scratch client issuance test (CSR only, no key returned)

Clarifying note on the flow, since it's easy to misstate: the **client** generates its own keypair and CSR; the **Function** returns only a signed **certificate**, never a key. The private key never transits the network in either direction.

```bash
mkdir -p ~/mtls-test && cd ~/mtls-test

# 1. Client generates its own keypair + CSR locally — private key never leaves this machine
openssl req -new -newkey rsa:2048 -nodes \
  -keyout client.key \
  -out client.csr \
  -subj "/CN=example-client"

# 2. Authenticate to the Function
TOKEN=$(az account get-access-token --resource https://management.azure.com --query accessToken -o tsv)

# 3. Submit CSR, receive signed certificate (no key in the response)
curl -s -X POST "https://generatemtlsv2.azurewebsites.net/api/issue" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @client.csr \
  -o client.crt

# 4. Get the current root CA public cert for verification
az keyvault certificate download \
  --vault-name PivotKV --name ca-root-cert \
  --file ca-cert.pem --encoding PEM

# 5. Inspect and verify
openssl x509 -in client.crt -noout -text
openssl verify -CAfile ca-cert.pem client.crt

# 6. Confirm the private key actually matches the issued cert
openssl x509 -noout -modulus -in client.crt | openssl md5
openssl rsa -noout -modulus -in client.key | openssl md5
# both outputs must be identical
```

### 7.13 End-to-end test from inside a real App Service (managed identity flow)

This validates the actual production flow — a client app authenticating with its own Managed Identity rather than an operator's CLI token.

**a. Create a real Azure AD App Registration for the Function's audience** (replaces the `management.azure.com` stand-in used for CLI testing):

```bash
az ad app create --display-name "signing-function-api"
# note the returned appId

appId=<paste-appId-here>
az ad app update --id $appId --identifier-uris "api://$appId"
```
Note: tenant policy on this subscription rejects arbitrary identifier URIs (e.g. `api://signing-function`) — the URI must embed the app's own ID or the tenant ID (`https://aka.ms/identifier-uri-formatting-error`).

**b. Point the Function at the real audience:**

```bash
az functionapp config appsettings set \
  --name GeneratemTLSv2 --resource-group rg-prototype \
  --settings EXPECTED_AUDIENCE="api://$appId"

az functionapp restart --name GeneratemTLSv2 --resource-group rg-prototype
```

**c. Enable Managed Identity on the client App Service and authorize it in policy:**

```bash
az webapp identity assign --name PivotAppService --resource-group rg-prototype

appPrincipalId=$(az webapp identity show --name PivotAppService --resource-group rg-prototype --query principalId -o tsv)

az functionapp config appsettings set \
  --name GeneratemTLSv2 --resource-group rg-prototype \
  --settings ALLOWED_CALLER_POLICY="${appPrincipalId}=example-client"

az functionapp restart --name GeneratemTLSv2 --resource-group rg-prototype
```

**d. Obtain a shell inside the App Service to run the real client-side test.**

Blocker encountered: `PivotAppService` was still running Azure's default placeholder image (`mcr.microsoft.com/appsvc/staticsite:latest`, visible via `az webapp sitecontainers list`), which has no SSH server, so `az webapp ssh` failed with "SSH endpoint unreachable" regardless of app state. Fix: deploy a minimal custom container with `openssl`, `curl`, `python3`, and an SSH server, built for this purpose:

```dockerfile
FROM python:3.11-slim
RUN apt-get update && apt-get install -y openssl curl openssh-server && \
    mkdir /var/run/sshd && \
    echo 'root:Docker!' | chpasswd && \
    sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    sed -i 's/#Port 22/Port 2222/' /etc/ssh/sshd_config
EXPOSE 2222 80
# App Service's readiness probe hits the main HTTP port (80) before SSH tunneling
# is allowed through — sshd alone starting is not sufficient; a listener on 80
# is also required, or az webapp ssh keeps reporting "app must be running"
CMD service ssh start && python3 -m http.server 80
```

```bash
docker build --platform linux/amd64 -t containerrestry-cgdqe7hee4hxe3ht.azurecr.io/appservice-test:latest .
docker push containerrestry-cgdqe7hee4hxe3ht.azurecr.io/appservice-test:latest

az webapp config container set \
  --name PivotAppService --resource-group rg-prototype \
  --docker-custom-image-name containerrestry-cgdqe7hee4hxe3ht.azurecr.io/appservice-test:latest \
  --docker-registry-server-url https://containerrestry-cgdqe7hee4hxe3ht.azurecr.io

az role assignment create \
  --assignee-object-id $appPrincipalId \
  --assignee-principal-type ServicePrincipal \
  --role AcrPull \
  --scope $(az acr show --name ContainerRestry --query id -o tsv)

az webapp config set --name PivotAppService --resource-group rg-prototype \
  --generic-configurations '{"acrUseManagedIdentityCreds": true}'
```

Second blocker encountered: `az webapp show` returned `State: QuotaExceeded`, and `az webapp log tail` failed with `403 Site Disabled`. Root cause: `PivotAppService` was still on its originally auto-provisioned **F1 (Free)** App Service Plan (`ASP-rgprototype-a3f0`), which has a tight daily CPU-minute quota and does not support custom Linux containers at all. Fix: move it onto the already-provisioned paid Linux B1 plan (`signing-function-plan`) rather than provision a new one, to avoid any additional subscription quota consumption:

```bash
planId=$(az appservice plan show --name signing-function-plan --resource-group rg-prototype --query id -o tsv)

az webapp update \
  --name PivotAppService --resource-group rg-prototype \
  --set serverFarmId=$planId

az webapp restart --name PivotAppService --resource-group rg-prototype
```

Once `state` shows `Running` and the container log confirms both `sshd` and the HTTP listener started:

```bash
az webapp ssh --name PivotAppService --resource-group rg-prototype
```

**e. Inside the App Service shell — generate CSR, fetch a real Managed Identity token, call the Function:**

App Service Linux containers expose identity via `IDENTITY_ENDPOINT`/`IDENTITY_HEADER` environment variables (not the VM-style `169.254.169.254` metadata endpoint):

```bash
openssl req -new -newkey rsa:2048 -nodes \
  -keyout client.key -out client.csr -subj "/CN=example-client"

curl -s "$IDENTITY_ENDPOINT?resource=api://$appId&api-version=2019-08-01" \
  -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" -o token.json

TOKEN=$(python3 -c "import json; print(json.load(open('token.json'))['access_token'])")

curl -i -X POST "https://generatemtlsv2.azurewebsites.net/api/issue" \
  -H "Authorization: Bearer $TOKEN" \
  --data-binary @client.csr -o client.crt
```

**Status at time of writing:** infrastructure blockers (placeholder image, F1 quota) were resolved; the final in-shell managed-identity issuance call had not yet been executed/confirmed successful.

---

## 8. Outstanding Work / Not Yet Production-Ready

The core signing mechanism (CSR in → Key Vault-signed certificate out, via a `crypto.Signer` bridging Go's standard library to Key Vault's `sign` API) is proven end-to-end. The following remain before this should be trusted for real traffic:

1. **Resolve the root CA `CA:TRUE` issue definitively** (§6.3) — confirm the `az rest`/`basic_constraints` approach or fall back to the Go bootstrap script.
2. **Real Azure AD App Registration** for the Function's audience, replacing the `management.azure.com` audience used for CLI-token testing (which is far too broad for production — it would accept any caller with basic Azure management-plane access as an authorized certificate requester).
3. **Real policy enforcement** — replace the permissive default in `isAllowed` with an actual per-identity subject allowlist (config-backed or database-backed).
4. **JWKS caching** — `aadKeyForKID` currently fetches from Microsoft's discovery endpoint on every request; needs caching (e.g., 15–60 minutes) before production load.
5. **App Service client-side integration** — wire the CSR-generation + managed-identity-token-request flow into the actual client application's startup process (currently only tested manually via `openssl` + CLI-issued tokens).
6. **Network exposure** — the Function currently accepts traffic from the public internet with `anonymous` auth level at the platform layer (application-level JWT validation is the only gate). Consider VNet integration + Private Endpoint for both the Function and Key Vault before production use.
7. **Audit logging** — enable Key Vault diagnostic logs and Function-level issuance logging (caller identity, requested subject, issued serial number, timestamp) for traceability and future revocation support.
8. **Revocation strategy** — not yet addressed; short-lived certs (7 days in the prototype) reduce but do not eliminate the need for a revocation story if requirements grow.
9. **Separate root vs. intermediate CA** — the prototype signs directly from the root; production should introduce an intermediate CA so the root can remain offline/unused day-to-day.
