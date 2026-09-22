//! Keeping a run's transcript from becoming a credential store — M10 §2.4.
//!
//! A `show running-config` prints hashed passwords and SNMP communities. A verbose HTTP
//! call prints an `Authorization` header. A run's transcript is the record an auditor
//! reads, and its failure mode is that it quietly becomes the most convenient place in
//! the product to steal secrets from.
//!
//! # This is a net, not a boundary, and saying so is the point
//!
//! A regex over arbitrary device output cannot be complete. Vendors invent syntax, and a
//! secret printed in a shape nobody anticipated goes through. What actually keeps the
//! transcript from being a credential store is three things together, of which this is
//! the weakest:
//!
//! 1. **The output is capped**, so a `show running-config` is truncated rather than
//!    stored. A configuration does not fit.
//! 2. **M10 §4 says plainly** that this is not where configuration backup lives, so
//!    nothing encourages a runbook that dumps one.
//! 3. **This.**
//!
//! A deployment that treats the redaction as a guarantee has misread it. A deployment
//! that keeps its transcripts under the same access control as its credentials has not.
//!
//! # What it does, and why it leaves the key
//!
//! `username netops password 7 0822455D0A16` becomes
//! `username netops password <redacted>` rather than disappearing. A reader has to be
//! able to tell that a secret *was* there, and whose — a line that silently vanished is a
//! transcript that lies about what the device said, and an auditor comparing two runs
//! would see a difference nobody caused.
//!
//! Everything after the word goes, including Cisco's `7` type marker. Keeping the marker
//! would read better and would need a rule that tells a type marker from a *short
//! secret*, which is guesswork — `community pub` is the case it gets wrong.

/// The most output kept per step.
///
/// Four kilobytes: enough for the output of every command a runbook step should be
/// producing, and far short of a configuration. A step whose output is truncated is a
/// step doing something M10 §4 says this is not for.
pub const MAX_OUTPUT: usize = 4096;

/// What is appended when output is cut.
pub const TRUNCATED: &str = "\n… truncated. A run transcript is not where configuration \
                             backup lives — see M10 §4.";

/// Words that introduce a secret on the rest of the line.
///
/// Matched case-insensitively as whole words. The value after them is replaced; the word
/// itself stays, so the line still says what kind of thing was there.
const SECRET_WORDS: &[&str] = &[
    "authorization",
    "community",
    "key",
    "passphrase",
    "password",
    "pre-shared-key",
    "psk",
    "secret",
    "token",
];

/// What replaces a secret.
pub const MASK: &str = "<redacted>";

/// Redact and cap a step's output.
///
/// Applied on the way in, before anything is stored, so there is no window in which the
/// unredacted form exists in a row.
#[must_use]
pub fn output(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(MAX_OUTPUT) + TRUNCATED.len());
    let mut in_pem = false;

    for line in raw.lines() {
        // A PEM block is the one case where the secret is not on the line that names it,
        // so it is tracked across lines rather than matched per line.
        if line.contains("-----BEGIN") && line.contains("PRIVATE KEY") {
            in_pem = true;
            out.push_str(line);
            out.push('\n');
            out.push_str(MASK);
            out.push('\n');
            continue;
        }
        if in_pem {
            if line.contains("-----END") {
                in_pem = false;
                out.push_str(line);
                out.push('\n');
            }
            // Every line between the markers is dropped, including the markers' own
            // trailing text. The `<redacted>` above is what says something was here.
            continue;
        }

        out.push_str(&line_redacted(line));
        out.push('\n');

        if out.len() > MAX_OUTPUT {
            break;
        }
    }

    if out.len() > MAX_OUTPUT {
        out.truncate(
            // Truncate on a character boundary. Device output is not guaranteed ASCII,
            // and slicing a multi-byte sequence in half panics.
            (0..=MAX_OUTPUT)
                .rev()
                .find(|i| out.is_char_boundary(*i))
                .unwrap_or(0),
        );
        out.push_str(TRUNCATED);
    }

    out
}

/// One line, with anything after a secret word replaced.
fn line_redacted(line: &str) -> String {
    let lowered = line.to_lowercase();

    // The earliest secret word on the line wins, because everything after it is suspect.
    let found = SECRET_WORDS
        .iter()
        .filter_map(|word| find_word(&lowered, word).map(|at| (at, word.len())))
        .min_by_key(|(at, _)| *at);

    let Some((at, len)) = found else {
        return line.to_owned();
    };

    let keep_to = at + len;
    let rest = &line[keep_to..];

    // Keep the punctuation and whitespace immediately after the word — the `:` of a
    // header, the space of a CLI — so the line still reads as what it was. Everything
    // from the first alphanumeric onward goes, which is why Cisco's `7` marker goes too.
    let boundary = rest
        .char_indices()
        .find(|(_, c)| c.is_alphanumeric() || *c == '$' || *c == '"' || *c == '\'')
        .map_or(rest.len(), |(i, _)| i);

    if boundary == rest.len() {
        // A line naming a secret word with nothing after it: `password` on its own, or a
        // header the device printed empty. Nothing to hide.
        return line.to_owned();
    }

    format!("{}{}{MASK}", &line[..keep_to], &rest[..boundary])
}

/// Where a whole word starts in an already-lowercased haystack.
///
/// Whole words for the same reason the deny-list in [`crate::validate`] uses them: a
/// substring match on `key` would redact `keyboard` and `monkey`, and a redaction with
/// false positives is a transcript that hides things nobody needed hidden.
fn find_word(haystack: &str, word: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(at) = haystack[from..].find(word) {
        let start = from + at;
        let end = start + word.len();

        let before_ok = start == 0
            || !haystack[..start]
                .chars()
                .next_back()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');
        let after_ok = end == haystack.len()
            || !haystack[end..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric() || c == '_');

        if before_ok && after_ok {
            return Some(start);
        }
        from = end;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cisco_password_hash_is_replaced_and_the_line_still_says_what_it_was() {
        // Everything after the word goes, including Cisco's `7` type marker. Keeping the
        // marker would read better and would need a rule that tells a type marker from a
        // *short secret* — and that rule is guesswork. `community pub` would be the case
        // it gets wrong.
        let got = output("username netops password 7 0822455D0A16");
        assert!(got.contains("username netops password <redacted>"), "{got}");
        assert!(!got.contains("0822455D0A16"), "{got}");
        assert!(
            got.starts_with("username netops"),
            "the line still says whose password it was: {got}"
        );
    }

    #[test]
    fn an_snmp_community_goes() {
        let got = output("snmp-server community pub1ic RO");
        assert!(!got.contains("pub1ic"), "{got}");
        assert!(got.contains("community <redacted>"), "{got}");
    }

    #[test]
    fn an_authorization_header_goes() {
        let got = output("> Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc.def");
        assert!(!got.contains("eyJhbGciOiJIUzI1NiJ9"), "{got}");
        assert!(got.contains("Authorization: <redacted>"), "{got}");
    }

    #[test]
    fn an_enable_secret_goes() {
        let got = output("enable secret 5 $1$mERr$hx5rVt7rPNoS4wqbXKX7m0");
        assert!(!got.contains("hx5rVt7rPNoS4wqbXKX7m0"), "{got}");
    }

    #[test]
    fn a_private_key_block_goes_entirely() {
        let raw = "-----BEGIN RSA PRIVATE KEY-----\n\
                   MIIEowIBAAKCAQEAx3f8...\n\
                   AoGBAKX7...\n\
                   -----END RSA PRIVATE KEY-----\n\
                   interface Gi0/1";
        let got = output(raw);
        assert!(!got.contains("MIIEowIBAAKCAQEAx3f8"), "{got}");
        assert!(!got.contains("AoGBAKX7"), "{got}");
        // The markers stay, so the transcript says a key was there rather than silently
        // skipping four lines.
        assert!(got.contains("-----BEGIN RSA PRIVATE KEY-----"), "{got}");
        assert!(got.contains("<redacted>"), "{got}");
        // And the output after the block is not lost.
        assert!(got.contains("interface Gi0/1"), "{got}");
    }

    #[test]
    fn ordinary_output_is_untouched() {
        // A redaction with false positives is a transcript that hides what nobody needed
        // hidden, and an operator who cannot read their own output stops using the
        // feature.
        for line in [
            "Gi0/1 is up, line protocol is up",
            "BGP neighbor is 10.0.0.1, remote AS 65001",
            "keyboard not found, press F1 to continue",
            "monkey-patch applied",
            "Building configuration...",
            "  Description: uplink to core",
        ] {
            let got = output(line);
            assert_eq!(got.trim_end(), line, "{line}");
        }
    }

    #[test]
    fn the_word_match_is_whole_words() {
        // `key` must not redact `keyboard` or `monkey`, for the same reason the deny-list
        // matches whole words.
        assert!(find_word("keyboard not found", "key").is_none());
        assert!(find_word("monkey business", "key").is_none());
        assert!(find_word("ssh key is set", "key").is_some());
        assert!(find_word("key", "key").is_some());
    }

    #[test]
    fn output_is_capped_and_says_why() {
        let huge = "interface Gi0/1\n".repeat(2000);
        let got = output(&huge);
        assert!(got.len() <= MAX_OUTPUT + TRUNCATED.len(), "{}", got.len());
        assert!(got.contains("truncated"), "{got}");
        // The message points at the decision rather than just saying "truncated", so
        // somebody whose runbook is producing this reads why it will not be stored.
        assert!(got.contains("M10 §4"), "{got}");
    }

    #[test]
    fn truncation_does_not_split_a_character() {
        // Device output is not guaranteed ASCII, and slicing a multi-byte sequence in
        // half panics. A transcript that crashes the runner is worse than one that is cut
        // a byte early.
        let multibyte = "descripción del enlace — núcleo\n".repeat(400);
        let got = output(&multibyte);
        assert!(got.len() <= MAX_OUTPUT + TRUNCATED.len());
        assert!(got.is_char_boundary(got.len()));
    }

    #[test]
    fn a_secret_word_with_nothing_after_it_is_left_alone() {
        // `password` on its own line, or a header the device printed empty. Replacing
        // nothing with `<redacted>` would invent a secret that was not there.
        for line in ["password", "Authorization:", "no snmp-server community"] {
            let got = output(line);
            assert_eq!(got.trim_end(), line, "{line}");
        }
    }

    #[test]
    fn the_earliest_secret_on_a_line_wins() {
        // Everything after the first one is suspect, so a second word later in the line
        // must not reset where the redaction starts.
        let got = output("set password abc token def");
        assert!(!got.contains("abc"), "{got}");
        assert!(!got.contains("def"), "{got}");
    }

    #[test]
    fn empty_output_stays_empty() {
        assert_eq!(output(""), "");
    }
}
