# Single sign-on

Connecting this product to an identity provider, and what it does with what comes back.

M12 §2.2 records *why* it is built this way; this file is for somebody setting it up.

---

## What it does

A person signs in at their identity provider. The provider sends back an ID token saying
who they are and which groups they belong to, and this product turns those groups into
roles using a mapping an operator has written down.

```
   browser ──▶ /auth/oidc/{id}/start ──▶ provider ──▶ /auth/oidc/callback ──▶ session
```

**It does not guess.** A group called `network-admins` grants nothing until somebody maps
it. A user whose groups map to nothing authenticates successfully and is refused — with
an audit entry saying which groups they had — rather than being given a default role.

**Local passwords still work** unless the organization requires SSO, which switches them
off for everyone except one named break-glass account.

---

## Before you start

Three things have to agree, and a mismatch in any of them produces a sign-in that fails
at the provider with a message that does not mention this product:

| here | at the provider |
|---|---|
| `UOPS_PUBLIC_URL` | the registered redirect URI, which is `<public url>/api/v1/auth/oidc/callback` |
| the **issuer** you configure | the `iss` in its tokens, character for character |
| the **client id** you configure | the application you registered |

`UOPS_PUBLIC_URL` is where a *browser* reaches this deployment — `https://uops.acme.com`,
not the address the server binds to. It is deliberately not derived from the request's
`Host` header: whoever controls that header would otherwise choose where a sign-in's
authorization code is sent.

The issuer is compared **exactly**. `https://idp.acme.com` and `https://idp.acme.com/`
are different issuers, and the one that works is whichever one the provider's own
discovery document says. Configuring it is one call:

```bash
curl -s https://idp.acme.com/.well-known/openid-configuration | jq -r .issuer
```

Use that string.

---

## Registering the application

### Microsoft Entra ID

1. **App registrations → New registration.** Redirect URI type *Web*, value
   `https://uops.acme.com/api/v1/auth/oidc/callback`.
2. **Certificates & secrets → New client secret.** Copy it now; it is shown once.
3. **Token configuration → Add groups claim.** Choose *Security groups* and, under the
   ID token column, tick **Emit groups as role claims** off and *Group ID* on.
4. The issuer is `https://login.microsoftonline.com/<tenant-guid>/v2.0`.

Entra ID sends **group object ids**, not names, so the mapping below is written with
GUIDs. That is a feature rather than an annoyance: renaming a group does not silently
change anybody's access here.

> Entra ID omits the groups claim entirely when a user is in more than about 200 groups,
> sending a `_claim_names` pointer to the Graph API instead. This product does not follow
> that pointer, so such a user maps to nothing and is refused. If that applies to your
> estate, restrict the claim to *Groups assigned to the application*.

### Okta

1. **Applications → Create App Integration → OIDC, Web Application.**
2. Sign-in redirect URI: `https://uops.acme.com/api/v1/auth/oidc/callback`.
3. **Sign On → Group claims filter**, or an `Authorization Server → Claims` entry named
   `groups` with a value expression like `getFilteredGroups(...)`.
4. The issuer is `https://acme.okta.com` for the org server, or
   `https://acme.okta.com/oauth2/<id>` for a custom one. They are different issuers and
   only one of them will be in the tokens.

Okta sends **group names**.

### Keycloak

1. **Clients → Create client.** Client authentication *On* for a confidential client.
2. Valid redirect URI: `https://uops.acme.com/api/v1/auth/oidc/callback`.
3. **Client scopes → `<client>-dedicated` → Add mapper → By configuration → Group
   Membership.** Token claim name `groups`, *Full group path* **off** — with it on, the
   claim values are `/noc` rather than `noc` and the mapping has to match that.
4. The issuer is `https://sso.acme.com/realms/acme`, path and all.

### A public client

If the provider will not issue a client secret, configure the provider here without one.
PKCE is always on and is not optional, so a public client is a supported configuration
rather than a weaker one. What it loses is the provider's assurance that the party
redeeming a code is this server; what PKCE gives is the assurance that it is the party
that *started* the sign-in, which is the property that matters in a browser flow.

---

## Configuring it here

Everything below needs the admin role on **every** tenant in the organization. See M12
§2.2 for why it is not "any tenant".

A client secret needs a key-encryption key — the same `UOPS_KEK_FILE` or `UOPS_KEK_HEX`
device credentials use. Without one the route refuses, in a sentence naming the variable,
rather than storing the secret in the clear.

```bash
# Create the provider. The issuer is fetched and checked before anything is written, so
# a typo is a message rather than a row that fails at somebody's first sign-in.
curl -X POST https://uops.acme.com/api/v1/sso/providers \
  -H 'Content-Type: application/json' -H "X-Uops-Csrf: $CSRF" -b "$COOKIES" \
  -d '{
        "name": "Acme SSO",
        "issuer": "https://login.microsoftonline.com/<tenant-guid>/v2.0",
        "client_id": "<application-id>",
        "client_secret": "<the secret>",
        "groups_claim": "groups"
      }'
```

```bash
# Map a group to a role on a tenant. One line per (group, tenant).
curl -X POST https://uops.acme.com/api/v1/sso/providers/$PROVIDER/grants \
  -H 'Content-Type: application/json' -H "X-Uops-Csrf: $CSRF" -b "$COOKIES" \
  -d '{"group": "<group id or name>", "tenant_id": "<tenant uuid>", "role": "operator"}'
```

The roles are `viewer`, `operator` and `admin`. A user in several mapped groups gets the
**highest** role on each tenant — so adding somebody to another group can never take
access away, and access never depends on the order of a JSON array the provider chose.

Then sign in. The button appears on the sign-in page by itself.

---

## Requiring SSO

```bash
curl -X PUT https://uops.acme.com/api/v1/sso/require \
  -H 'Content-Type: application/json' -H "X-Uops-Csrf: $CSRF" -b "$COOKIES" \
  -d '{"required": true}'
```

**Create the break-glass account first.** This switches off password login for every
account in the organization except the one marked break-glass, and there is exactly one
of those. It is what you will use on the day the identity provider is unreachable, an
expired signing certificate breaks every token, or somebody deletes the application
registration. Keep its password somewhere that does not depend on being signed in to
this product.

The call is refused if the organization has no enabled identity provider, which is the
one version of this mistake that locks everybody out in a single request.

Every use of the break-glass account is an audit event, visible at
`GET /api/v1/sso/audit` along with every sign-in, every refusal, and every change to this
configuration.

---

## When a sign-in fails

The browser is always told the same thing: *sign-in failed*. Which check failed is in the
**server log**, because telling a browser that the audience was wrong confirms that a
token was well-formed and correctly signed, which is useful to somebody working out what
to forge next.

So: read the server log. The commonest causes, in order:

| log line contains | what it is |
|---|---|
| `redirect_uri` | `UOPS_PUBLIC_URL` and the registered URI disagree — usually a trailing slash or `http` against `https` |
| `claim iss` | the issuer configured here is not the one in the tokens. Ask the discovery document |
| `claim aud` | the client id configured here is not the application the token was minted for |
| `none of the ... group(s) in the token is mapped` | authentication worked; nothing is mapped yet. The log names the groups that arrived |
| `the token carried no group claim` | the provider is not releasing groups. That is configured at the provider, not here |
| `signature did not verify` | rare, and usually a provider mid-rotation. The key set refreshes on an unknown key id, at most once a minute |
| `this callback does not belong to a sign-in this browser started` | a stale tab, a bookmarked callback URL, or a genuine cross-site attempt |

A disabled provider answers **404**, not "disabled" — which of a company's providers are
switched off is not something an unauthenticated caller should be able to enumerate.

---

## What this does not do yet

**SAML.** OIDC first because every provider an enterprise is likely to have speaks it,
the libraries are smaller, and JSON over HTTP is a meaningfully smaller attack surface
than signed XML for something deployed on-premise and patched slowly.

**SCIM.** A user is provisioned on first sign-in, and their roles are reconciled from the
provider's groups on *every* sign-in — so removing somebody from a group takes their
access away the next time they sign in. What SCIM would add is prompt **de**provisioning
for somebody who never signs in again. Until it exists, disabling the account at the
provider stops new sessions, and disabling it here ends the ones already open.

**Single logout.** Signing out here ends the session here. It does not end the session at
the identity provider, so signing in again may not ask for a password.
