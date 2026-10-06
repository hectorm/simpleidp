# Simple IdP

Minimal OIDC Identity Provider that implements the Authorization Code flow with PKCE and the Client Credentials grant.

## Why

I need an IdP for local development and integration testing. Keycloak is more than capable, but too complex for this specific use case, and Dex, while lighter, doesn't implement everything I need for testing. So, with the help of an LLM, I've developed this simple IdP. This isn't strictly "vibe-coded" because I at least guided and verified the low-level implementation, but naturally, this shouldn't be used for any production purposes. It was developed solely to address a use case of my own. If you find this useful, go ahead and use it, but I consider this finished unless I find a bug or need to extend the implementation.

## Endpoints

The identity provider endpoints are derived from the issuer URL:

| Endpoint      | URL                                         |
| ------------- | ------------------------------------------- |
| Profile       | `<ISSUER>/`                                 |
| Login         | `<ISSUER>/login`                            |
| Discovery     | `<ISSUER>/.well-known/openid-configuration` |
| Authorization | `<ISSUER>/authorize`                        |
| Token         | `<ISSUER>/token`                            |
| UserInfo      | `<ISSUER>/userinfo`                         |
| JWKS          | `<ISSUER>/jwks`                             |
| Introspection | `<ISSUER>/introspect`                       |
| Revocation    | `<ISSUER>/revoke`                           |
| End session   | `<ISSUER>/end-session`                      |

The healthcheck endpoint is always served at `/healthz`, regardless of the issuer path.

## Configuration

All configuration is done through environment variables. At least one client and one user must be configured.

### General

| Variable                            | Description                                                       |
| ----------------------------------- | ----------------------------------------------------------------- |
| `SIMPLE_IDP_LISTEN`                 | Listen address (default `:8227`)                                  |
| `SIMPLE_IDP_ISSUER`                 | Issuer URL as seen by clients (required)                          |
| `SIMPLE_IDP_TITLE`                  | Login page title (default `Simple IdP`)                           |
| `SIMPLE_IDP_LOGO`                   | Logo URL or data URI shown instead of the title (default: none)   |
| `SIMPLE_IDP_FAVICON`                | Favicon URL or data URI (default: blank icon)                     |
| `SIMPLE_IDP_ACCENT_COLOR`           | Accent color for the pages (default `oklch(49% 0.19 264)`)        |
| `SIMPLE_IDP_COLOR_SCHEME`           | CSS `color-scheme` value for the pages (default `light dark`)     |
| `SIMPLE_IDP_LANGUAGE`               | Language for every page (default: negotiated)                     |
| `SIMPLE_IDP_EDIT_PROFILE`           | Let users edit their profile, not persisted (default `false`)     |
| `SIMPLE_IDP_SESSION_IDLE_TTL`       | Session idle timeout (default `30m`)                              |
| `SIMPLE_IDP_SESSION_MAX_TTL`        | Session maximum lifetime (default `10h`)                          |
| `SIMPLE_IDP_ACCESS_TOKEN_TTL`       | Access and ID token lifetime (default `5m`)                       |
| `SIMPLE_IDP_REFRESH_TOKEN_IDLE_TTL` | Refresh token idle timeout (default `30m`)                        |
| `SIMPLE_IDP_REFRESH_TOKEN_MAX_TTL`  | Refresh token maximum lifetime (default `10h`)                    |
| `SIMPLE_IDP_KEY_ID`                 | JWKS key ID (default `simpleidp`)                                 |
| `SIMPLE_IDP_KEY_FILE`               | PEM file for PKCS8 RSA private key (generated in memory if empty) |
| `SIMPLE_IDP_KEY_B64`                | Base64-encoded PKCS8 RSA private key (alternative to `KEY_FILE`)  |
| `SIMPLE_IDP_LOG_LEVEL`              | Log level: `debug`, `info`, `warn` or `error` (default `info`)    |

### Clients

Clients are configured with a label prefix. The label is arbitrary and only used for grouping.

| Variable                                                        | Description                                                          |
| --------------------------------------------------------------- | -------------------------------------------------------------------- |
| `SIMPLE_IDP_CLIENT_<LABEL>_ID`                                  | Client ID                                                            |
| `SIMPLE_IDP_CLIENT_<LABEL>_SECRET`                              | Client secret (optional for loopback/native clients)                 |
| `SIMPLE_IDP_CLIENT_<LABEL>_AUDIENCE`                            | `aud` claim of access tokens (default: client ID)                    |
| `SIMPLE_IDP_CLIENT_<LABEL>_REDIRECT_URL`                        | Allowed redirect URIs (whitespace-separated, optional with a secret) |
| `SIMPLE_IDP_CLIENT_<LABEL>_POST_LOGOUT_REDIRECT_URL`            | Allowed post-logout redirect URIs (whitespace-separated, optional)   |
| `SIMPLE_IDP_CLIENT_<LABEL>_BACKCHANNEL_LOGOUT_URI`              | Back-channel logout URI (optional)                                   |
| `SIMPLE_IDP_CLIENT_<LABEL>_BACKCHANNEL_LOGOUT_SESSION_REQUIRED` | Require `sid` in logout token (optional, default `false`)            |

### Users

Users are configured the same way as clients, with a label prefix.

| Variable                                     | Description                                        |
| -------------------------------------------- | -------------------------------------------------- |
| `SIMPLE_IDP_USER_<LABEL>_USERNAME`           | Login username (required)                          |
| `SIMPLE_IDP_USER_<LABEL>_PASSWORD`           | Login password (required)                          |
| `SIMPLE_IDP_USER_<LABEL>_TOTP_SECRET`        | Base32 TOTP secret (default: empty)                |
| `SIMPLE_IDP_USER_<LABEL>_SUB`                | `sub` claim (default: hex SHA-256 of `<LABEL>`)    |
| `SIMPLE_IDP_USER_<LABEL>_NAME`               | `name` claim (default: `<USERNAME>`)               |
| `SIMPLE_IDP_USER_<LABEL>_PREFERRED_USERNAME` | `preferred_username` claim (default: `<USERNAME>`) |
| `SIMPLE_IDP_USER_<LABEL>_EMAIL`              | `email` claim (default: `<USERNAME>@localhost`)    |
| `SIMPLE_IDP_USER_<LABEL>_EMAIL_VERIFIED`     | `email_verified` claim (default: `true`)           |
| `SIMPLE_IDP_USER_<LABEL>_PROFILE`            | `profile` claim (default: empty)                   |
| `SIMPLE_IDP_USER_<LABEL>_PICTURE`            | `picture` claim (default: empty)                   |
| `SIMPLE_IDP_USER_<LABEL>_LOCALE`             | `locale` claim (default: empty)                    |
| `SIMPLE_IDP_USER_<LABEL>_GROUPS`             | Comma-separated `groups` claim (default: empty)    |
| `SIMPLE_IDP_USER_<LABEL>_ROLES`              | Comma-separated `roles` claim (default: empty)     |
