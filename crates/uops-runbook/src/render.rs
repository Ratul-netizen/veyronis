//! Substitution, not evaluation — M10 §2.1.
//!
//! `{{ resource.name }}` is replaced by a named value from the run's context. That is the
//! whole of it. There is no expression language, no function call, no conditional and no
//! arithmetic, because an expression language is where injection lives and where "the
//! runbook did something nobody predicted" starts.
//!
//! # Values are validated, not quoted, and that is the interesting decision
//!
//! The obvious design is to escape a value for the transport it is going into. It does not
//! survive contact with the target: `ssh.command` does not run in a POSIX shell. It runs
//! in a Cisco IOS CLI, or a `JunOS` CLI, or a busybox on a PDU, and their quoting rules
//! are different from each other and from `sh`. A product that shell-quoted `10.0.0.1`
//! into `'10.0.0.1'` would break on the majority of the devices this is for.
//!
//! So a substituted value must instead **be** safe rather than be made safe: letters,
//! digits, and `. : - _ / @`. That covers hostnames, addresses, interface names, VLAN
//! ids and peer identifiers — everything that actually appears — and refuses the
//! characters that turn one command into two.
//!
//! Anything else is a refusal at render time, naming the character. Not a silent strip: a
//! value quietly stripped of a semicolon is a command an operator reviewed in one form and
//! ran in another.
//!
//! # And an unknown placeholder is an error
//!
//! Not an empty string. `rm -rf /{{ path }}` with `path` unset would render as `rm -rf /`,
//! which is the single most expensive empty-string substitution in computing. A template
//! naming something the context does not have is a runbook that cannot run.

use std::collections::BTreeMap;

use crate::error::{Error, Result};

/// Characters a substituted value may contain, beyond letters and digits.
///
/// Each one earns its place: `.` and `:` for addresses, `-` and `_` for names, `/` for
/// interfaces like `gi0/1` and paths, `@` for `user@host`. Deliberately absent are the
/// space, the semicolon, the pipe, every quote, every bracket, the backtick, `$`, `&`,
/// `\` and the newline — which between them are how one command becomes two.
pub const ALLOWED_PUNCTUATION: &[char] = &['.', ':', '-', '_', '/', '@'];

/// The values a run substitutes into its steps.
///
/// A flat map on purpose. Nested paths would need a path language, a path language needs a
/// parser, and a parser is the beginning of the expression language this refuses to be.
/// `resource.name` is a *key* containing a dot, not a traversal.
pub type Context = BTreeMap<String, String>;

/// The longest a substituted value may be.
///
/// A bound rather than a guess: an interface name is short, an address is short, and a
/// four-kilobyte value arriving in a template is something other than what the author had
/// in mind.
pub const MAX_VALUE_LEN: usize = 128;

/// Render a template against a context.
///
/// # Errors
///
/// [`Error::UnknownPlaceholder`] when the template names something the context does not
/// have — see the module docs for why that is not an empty string. [`Error::UnsafeValue`]
/// when a value contains a character that could end the command it is going into.
/// [`Error::MalformedTemplate`] for an unclosed `{{`.
pub fn render(template: &str, context: &Context) -> Result<String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after = &rest[open + 2..];

        let Some(close) = after.find("}}") else {
            return Err(Error::MalformedTemplate(
                "a `{{` with no closing `}}`".to_owned(),
            ));
        };

        let name = after[..close].trim();
        if name.is_empty() {
            return Err(Error::MalformedTemplate("an empty `{{ }}`".to_owned()));
        }
        // A placeholder that itself contains `{{` means somebody nested them, which this
        // does not support and should not guess at.
        if name.contains('{') || name.contains('}') {
            return Err(Error::MalformedTemplate(format!(
                "the placeholder {name:?} contains a brace"
            )));
        }

        let value = context
            .get(name)
            .ok_or_else(|| Error::UnknownPlaceholder(name.to_owned()))?;

        check_value(name, value)?;
        out.push_str(value);

        rest = &after[close + 2..];
    }

    out.push_str(rest);
    Ok(out)
}

/// Every placeholder a template names, in order, without rendering it.
///
/// Used to tell an author at *save* time which values their runbook will need, rather than
/// at run time when the answer is a failure.
#[must_use]
pub fn placeholders(template: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        let after = &rest[open + 2..];
        let Some(close) = after.find("}}") else { break };
        let name = after[..close].trim();
        if !name.is_empty() && !name.contains('{') {
            found.push(name.to_owned());
        }
        rest = &after[close + 2..];
    }
    found
}

/// Whether a value may be substituted at all.
///
/// # Errors
///
/// [`Error::UnsafeValue`], naming the character.
pub fn check_value(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        // An empty value is the `rm -rf /{{ path }}` case even when the key exists.
        return Err(Error::UnsafeValue {
            name: name.to_owned(),
            because: "it is empty, and an empty substitution silently changes what a \
                      command means"
                .to_owned(),
        });
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(Error::UnsafeValue {
            name: name.to_owned(),
            because: format!("it is {} characters, past {MAX_VALUE_LEN}", value.len()),
        });
    }

    if let Some(bad) = value
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && !ALLOWED_PUNCTUATION.contains(c))
    {
        return Err(Error::UnsafeValue {
            name: name.to_owned(),
            because: format!(
                "it contains {bad:?}. A substituted value may hold letters, digits and \
                 {} — the quoting rules of a network CLI are not a shell's, so the \
                 product refuses the character rather than trying to escape it",
                ALLOWED_PUNCTUATION.iter().collect::<String>()
            ),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context(pairs: &[(&str, &str)]) -> Context {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn a_value_is_substituted() {
        let ctx = context(&[("peer", "10.0.0.1"), ("resource.name", "core-sw-01")]);
        assert_eq!(
            render("clear bgp neighbor {{ peer }}", &ctx).unwrap(),
            "clear bgp neighbor 10.0.0.1"
        );
        assert_eq!(
            render("{{resource.name}}: {{ peer }}", &ctx).unwrap(),
            "core-sw-01: 10.0.0.1"
        );
    }

    #[test]
    fn a_template_with_no_placeholder_is_itself() {
        assert_eq!(
            render("show bgp summary", &Context::new()).unwrap(),
            "show bgp summary"
        );
    }

    #[test]
    fn an_unknown_placeholder_is_an_error_and_not_an_empty_string() {
        // The single most expensive empty-string substitution in computing.
        let err = render("rm -rf /{{ path }}", &Context::new()).unwrap_err();
        assert!(matches!(err, Error::UnknownPlaceholder(n) if n == "path"));
    }

    #[test]
    fn an_empty_value_is_refused_even_when_the_key_exists() {
        // The same failure one step later: the key is there and the value is not.
        let err = render("rm -rf /{{ path }}", &context(&[("path", "")])).unwrap_err();
        assert!(matches!(err, Error::UnsafeValue { .. }), "{err:?}");
    }

    #[test]
    fn a_value_cannot_end_the_command_it_is_going_into() {
        // Every one of these turns one reviewed command into two unreviewed ones.
        for hostile in [
            "10.0.0.1; reload",
            "10.0.0.1 && reload",
            "10.0.0.1 | sh",
            "10.0.0.1\nreload",
            "$(reload)",
            "`reload`",
            "10.0.0.1'",
            "10.0.0.1\"",
            "a b",
        ] {
            let ctx = context(&[("peer", hostile)]);
            let result = render("clear bgp neighbor {{ peer }}", &ctx);
            assert!(
                matches!(result, Err(Error::UnsafeValue { .. })),
                "{hostile:?} was substituted: {result:?}"
            );
        }
    }

    #[test]
    fn the_values_that_actually_appear_are_allowed() {
        for ordinary in [
            "10.0.0.1",
            "2001:db8::1",
            "core-sw-01",
            "core-sw-01.example.com",
            "gi0/1",
            "TenGigE0/0/0/1",
            "vlan_100",
            "admin@core-sw-01",
            "65001",
        ] {
            let ctx = context(&[("v", ordinary)]);
            assert_eq!(render("{{ v }}", &ctx).unwrap(), ordinary, "{ordinary}");
        }
    }

    #[test]
    fn the_refusal_names_the_character() {
        // An operator whose runbook will not render needs to know which character, not
        // that "the value is invalid".
        let ctx = context(&[("peer", "10.0.0.1; reload")]);
        let Err(Error::UnsafeValue { name, because }) =
            render("clear bgp neighbor {{ peer }}", &ctx)
        else {
            panic!("expected a refusal")
        };
        assert_eq!(name, "peer");
        assert!(because.contains('\''), "{because}");
    }

    #[test]
    fn an_unclosed_placeholder_is_malformed_rather_than_ignored() {
        // Ignoring it would render `show {{ peer` literally and send a command nobody
        // wrote.
        assert!(matches!(
            render("show {{ peer", &Context::new()),
            Err(Error::MalformedTemplate(_))
        ));
        assert!(matches!(
            render("show {{ }}", &Context::new()),
            Err(Error::MalformedTemplate(_))
        ));
        assert!(matches!(
            render("show {{ {{peer}} }}", &Context::new()),
            Err(Error::MalformedTemplate(_))
        ));
    }

    #[test]
    fn there_is_no_expression_language() {
        // Each of these is a feature some templating library has, and each one is a way
        // for a reviewed runbook to do something unreviewed. They are placeholders here
        // and nothing else, so they are simply names the context does not have.
        for attempt in [
            "{{ 1 + 1 }}",
            "{{ peer | lower }}",
            "{{ range .Items }}",
            "{{ include \"other\" }}",
        ] {
            assert!(
                render(attempt, &Context::new()).is_err(),
                "{attempt} rendered"
            );
        }
    }

    #[test]
    fn a_value_cannot_smuggle_a_placeholder() {
        // Rendering is one pass. A value containing `{{ }}` is substituted literally and
        // never re-scanned, so a value cannot expand into another lookup.
        let ctx = context(&[("a", "b"), ("b", "10.0.0.1")]);
        // `{{ a }}` renders as `b`, and the result is not rendered again.
        assert_eq!(render("{{ a }}", &ctx).unwrap(), "b");
    }

    #[test]
    fn placeholders_are_listed_without_rendering() {
        assert_eq!(
            placeholders("clear bgp neighbor {{ peer }} on {{ resource.name }}"),
            vec!["peer".to_owned(), "resource.name".to_owned()]
        );
        assert_eq!(placeholders("show bgp summary"), Vec::<String>::new());
        // An unclosed one stops the scan rather than guessing.
        assert_eq!(placeholders("show {{ peer"), Vec::<String>::new());
    }

    #[test]
    fn an_oversized_value_is_refused() {
        let long = "a".repeat(MAX_VALUE_LEN + 1);
        let ctx = context(&[("v", long.as_str())]);
        assert!(matches!(
            render("{{ v }}", &ctx),
            Err(Error::UnsafeValue { .. })
        ));
    }
}
