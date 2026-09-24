//! The response headers every answer carries, and the one promise they enforce.
//!
//! # Why this exists
//!
//! `PLAN` line 86: *"No phone-home, ever. No auto-update check, no crash reporting, no
//! license callback."* Thirteen milestones were built and nothing enforced it — it was
//! true by habit. `docs/packaging.md` §6 is the decision; this is half of it, and the
//! more important half.
//!
//! A grep over `crates/` catches a phone-home somebody wrote on purpose, which is the
//! easy case. It cannot see the web bundle, where one would arrive by accident: a
//! thousand-package dependency tree, any member of which can fetch on import, in a
//! bundle no reviewer reads. `connect-src 'self'` is what makes that request *fail*
//! rather than be absent by luck.
//!
//! The policy was measured against the built bundle before being written, not guessed —
//! the accounting is in that document. Every third-party URL in `web/dist` is an inert
//! string: an XML namespace, a React error-docs link, a three.js paper citation. There is
//! no `eval`, no `new Function`, no worker and no wasm, which is why `script-src` needs
//! no escape hatch.
//!
//! # The one concession
//!
//! `style-src` carries `'unsafe-inline'`. Nineteen components set a style attribute from
//! data — a meter's width, a status colour, a tree's indent — and those are values, not
//! stylesheets. `style-src-attr 'unsafe-inline'` is what this actually wants, and Firefox
//! does not implement it: an unsupported directive falls back to `style-src`, so the
//! tighter policy would break every meter in Firefox. Moving them to CSS custom
//! properties does not help, because setting one is still a style attribute.
//!
//! What it costs is bounded: with an injection point an attacker could style the page,
//! including selector-based exfiltration of attribute values. It does not permit script.
//!
//! # No HSTS
//!
//! TLS is terminated at the operator's proxy — the workspace manifest says so — so this
//! process cannot know whether it is reachable over HTTPS. A process that asserts HSTS
//! while being served over plain HTTP on a closed management network makes that
//! installation unreachable, and the operator cannot undo it from their side for as long
//! as the `max-age` they never set. It belongs in their proxy.

use axum::Router;
use axum::http::{HeaderValue, header};
use tower_http::set_header::SetResponseHeaderLayer;

/// The Content-Security-Policy every response carries.
///
/// One string rather than a builder: this is a policy to be read and argued with in
/// review, and a policy assembled from parts is one nobody can see the whole of.
pub const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self'; \
     connect-src 'self'; \
     img-src 'self' data:; \
     font-src 'self'; \
     style-src 'self' 'unsafe-inline'; \
     object-src 'none'; \
     frame-ancestors 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     worker-src 'none'";

/// `no-referrer`, not `same-origin`.
///
/// This console's URLs carry resource, incident and tenant identifiers. A `Referer` on an
/// outbound navigation is a small leak of an estate's shape, and there is nothing this
/// product needs to send one to.
const REFERRER_POLICY: &str = "no-referrer";

/// Add the security headers to every response the process produces.
///
/// Applied last, over the static file service as well as the API, because a policy that
/// covers the JSON and not the page it is rendered in covers nothing — the page is where
/// a browser would execute the request being forbidden.
pub fn secured(app: Router) -> Router {
    // `overriding`, not `if_not_present`: if anything downstream ever sets one of these,
    // the stricter policy of the two should not be the one that loses to an accident.
    app.layer(SetResponseHeaderLayer::overriding(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    ))
    .layer(SetResponseHeaderLayer::overriding(
        header::REFERRER_POLICY,
        HeaderValue::from_static(REFERRER_POLICY),
    ))
    // Duplicates `frame-ancestors 'none'` for anything predating CSP 2. Cheap, and the
    // kind of thing a procurement scan asks for by name.
    .layer(SetResponseHeaderLayer::overriding(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The directives that carry the no-phone-home promise are present and are `'self'`.
    ///
    /// Named for what it protects rather than for the string it reads: `connect-src` is
    /// the one that turns `PLAN`'s promise into something a browser refuses, and
    /// `default-src` is what covers the fetch destinations nobody thought to name.
    #[test]
    fn a_dependency_cannot_reach_a_third_party() {
        for directive in ["default-src 'self'", "connect-src 'self'"] {
            assert!(
                CONTENT_SECURITY_POLICY.contains(directive),
                "{directive} is not in the policy, so a phone-home would succeed"
            );
        }
    }

    /// No directive permits a host, a scheme-wide source, or a wildcard.
    ///
    /// This is the mutation that matters: a policy stays *shaped* like a policy while
    /// somebody adds `connect-src 'self' https://telemetry.example.com` to make one
    /// feature work, and every reader afterwards sees a CSP and stops looking. `data:`
    /// is allowed on images only, and asserted below to be exactly that one.
    #[test]
    fn no_directive_allows_an_outside_source() {
        for forbidden in ["*", "http://", "https://", "ws:", "wss:", "blob:"] {
            assert!(
                !CONTENT_SECURITY_POLICY.contains(forbidden),
                "the policy allows {forbidden}, which is a hole in connect-src by another \
                 name: {CONTENT_SECURITY_POLICY}"
            );
        }

        // `data:` is a real source and belongs to exactly one directive. Anywhere else it
        // is an exfiltration or an injection channel — `data:` on script-src especially.
        assert_eq!(
            CONTENT_SECURITY_POLICY.matches("data:").count(),
            1,
            "data: appears more than once; it is for img-src alone"
        );
        assert!(CONTENT_SECURITY_POLICY.contains("img-src 'self' data:"));
    }

    /// Script may not be inlined or evaluated, and the concession is on style alone.
    ///
    /// The bundle has no `eval` and no inline script — verified against `web/dist`, not
    /// assumed — so there is nothing to trade for here. If a dependency later needs
    /// `'unsafe-eval'`, this test is the conversation about it rather than a quiet commit.
    #[test]
    fn the_only_inline_concession_is_style() {
        assert!(!CONTENT_SECURITY_POLICY.contains("'unsafe-eval'"));
        assert!(
            !CONTENT_SECURITY_POLICY.contains("script-src 'self' 'unsafe-inline'"),
            "inline script is permitted, which defeats the policy"
        );
        assert_eq!(
            CONTENT_SECURITY_POLICY.matches("'unsafe-inline'").count(),
            1,
            "there is more than one inline concession; §6.2 argues for exactly one"
        );
        assert!(CONTENT_SECURITY_POLICY.contains("style-src 'self' 'unsafe-inline'"));
    }

    /// The header value is constructible, which `from_static` decides at runtime.
    ///
    /// `HeaderValue::from_static` panics on a byte a header may not carry. The policy is
    /// a long hand-written string spanning continuation lines, and a stray newline in it
    /// would panic on the first request rather than at compile time — which is to say,
    /// in front of an operator rather than in CI.
    #[test]
    fn the_policy_is_a_legal_header_value() {
        let value = HeaderValue::from_static(CONTENT_SECURITY_POLICY);
        assert_eq!(value.to_str().expect("ascii"), CONTENT_SECURITY_POLICY);
        assert!(
            !CONTENT_SECURITY_POLICY.contains('\n'),
            "a newline would split the header"
        );
        // The line continuations in the constant are the usual way to get a double space
        // into a directive list. Harmless to a browser, and a sign the string was edited
        // without being read.
        assert!(
            !CONTENT_SECURITY_POLICY.contains("  "),
            "double space in the policy: {CONTENT_SECURITY_POLICY}"
        );
    }
}
