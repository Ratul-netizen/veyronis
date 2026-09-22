//! The message grammars this product reads — M11 §2.2.
//!
//! # Shapes, not vendors, and the count is the control
//!
//! The pressure on this file is to grow a parser per vendor per product per firmware
//! version. That set is unbounded, it is somebody else's release schedule, and every entry
//! in it is a pattern that silently stops matching. A monitoring product with three hundred
//! parsers has three hundred things that fail quietly.
//!
//! So this is a fixed, small set of **grammars**. A grammar is stable in a way a vendor's
//! format is not: `key=value` pairs have looked the same since the 1990s, CEF is a
//! published standard, and JSON is JSON. Several vendors share each one, which is the whole
//! reason it is worth writing.
//!
//! [`SHAPES`] has an asserted length. Adding a fifth is a deliberate act with a failing
//! test attached — the same mechanism `uops_profile::builtin::all` uses to hold the
//! built-in profiles at five.
//!
//! # A shape that does not match produces nothing, and that is the correct answer
//!
//! An unrecognised message is not an error, a warning, or a dropped log. It stays a log
//! line: stored, indexed, searchable, on the timeline. Producing no event is what the
//! product *should* do when it does not understand something, and the alternative — a
//! half-parsed event with three fields and a guess — is worse than silence because
//! something downstream will count it.
//!
//! # There is no regex engine here
//!
//! Every shape is hand-written and reads top to bottom. That is a deliberate cost: a
//! grammar somebody can read beats a pattern nobody can, and this is the file a customer's
//! security team will ask to see.

use std::collections::BTreeMap;

/// One message grammar.
///
/// The variants are the commitment. A vendor is not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// `src=1.2.3.4 dst=5.6.7.8 act=deny` — space-separated `key=value`, values optionally
    /// quoted.
    ///
    /// The most common firewall body there is: Fortinet, several Cisco ASA message classes,
    /// `pfSense`, `SonicWall` and most things that grew out of `iptables` logging.
    KeyValue,
    /// `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|key=value key=value`
    ///
    /// `ArcSight`'s Common Event Format. A published standard with a fixed header, which is
    /// what makes it worth having as its own shape: the header carries the vendor and the
    /// event name without any guessing, and the extension is the `KeyValue` grammar again.
    Cef,
    /// A JSON object as the whole body.
    ///
    /// Only one level is read. A nested object is kept under its own key as text rather
    /// than flattened with invented separators — a flattening convention is a thing
    /// consumers have to learn, and this product already has one for RFC 5424.
    Json,
    /// RFC 5424 structured data, already flattened by `uops-syslog` into attributes.
    ///
    /// The one shape whose parsing happened upstream. It is listed here because it is a
    /// grammar this product reads, and leaving it out would make [`SHAPES`] a lie about
    /// what is understood.
    StructuredData,
}

/// Every grammar, in the order they are tried.
///
/// **The length is asserted.** See the module docs.
pub const SHAPES: &[Shape] = &[
    // CEF first: a CEF body's extension is `KeyValue`, so trying `KeyValue` first would
    // match the extension and throw the header away.
    Shape::Cef,
    Shape::Json,
    Shape::KeyValue,
    Shape::StructuredData,
];

/// How many `key=value` pairs a body needs before it counts as that shape.
///
/// One pair is not a grammar. `Started service=sshd` is an English sentence that happens
/// to contain an equals sign, and treating it as a structured message produces an event
/// with one field and no meaning — which something downstream will then count.
pub const MIN_PAIRS: usize = 3;

/// What a shape extracted: raw vendor keys, before the ECS mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parsed {
    pub shape: Shape,
    pub fields: BTreeMap<String, String>,
    /// From CEF's header, when there is one. `None` for every other shape — the product
    /// takes a vendor from the *resource*, not from a message, and this is the one case
    /// where the message states it in a standard position.
    pub vendor: Option<String>,
    /// CEF's event name. A sentence the device wrote about itself.
    pub name: Option<String>,
}

/// Try every shape, in order, and take the first that matches.
///
/// Returns `None` for a body no grammar recognises, which is the ordinary case and not a
/// failure — see the module docs.
#[must_use]
pub fn parse(body: &str, structured: &BTreeMap<String, String>) -> Option<Parsed> {
    for shape in SHAPES {
        let found = match shape {
            Shape::Cef => cef(body),
            Shape::Json => json(body),
            Shape::KeyValue => key_value(body),
            Shape::StructuredData => structured_data(structured),
        };
        if let Some(parsed) = found {
            return Some(parsed);
        }
    }
    None
}

// ---- key=value ------------------------------------------------------------------

/// `src=1.2.3.4 dst=5.6.7.8 msg="a sentence with spaces"`
///
/// Quoted values may contain spaces; unquoted ones end at the next space. A key is
/// everything back to the previous space, which is what makes `foo bar=baz` yield `bar`
/// and not `foo bar`.
fn key_value(body: &str) -> Option<Parsed> {
    let fields = pairs(body);
    if fields.len() < MIN_PAIRS {
        return None;
    }
    Some(Parsed {
        shape: Shape::KeyValue,
        fields,
        vendor: None,
        name: None,
    })
}

/// The `key=value` scanner, shared by [`key_value`] and CEF's extension.
fn pairs(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;

    while i < bytes.len() {
        // Find the next `=`.
        let Some(eq) = (i..bytes.len()).find(|&n| bytes[n] == '=') else {
            break;
        };

        // The key is back to the previous space. Nothing before the first space in
        // `interface Gi0/1 src=…` becomes part of the key.
        let start = (i..eq).rev().find(|&n| bytes[n].is_whitespace()).map_or(i, |n| n + 1);
        let key: String = bytes[start..eq].iter().collect();

        // The value: quoted runs to the closing quote, unquoted to the next space.
        let (value, next) = if bytes.get(eq + 1) == Some(&'"') {
            let from = eq + 2;
            match (from..bytes.len()).find(|&n| bytes[n] == '"') {
                Some(close) => (bytes[from..close].iter().collect::<String>(), close + 1),
                // An unterminated quote. Take the rest rather than dropping the pair: a
                // truncated message is common and the value up to the cut is still a value.
                None => (bytes[from..].iter().collect::<String>(), bytes.len()),
            }
        } else {
            let from = eq + 1;
            let end = (from..bytes.len())
                .find(|&n| bytes[n].is_whitespace())
                .unwrap_or(bytes.len());
            (bytes[from..end].iter().collect::<String>(), end)
        };

        if !key.trim().is_empty() {
            out.entry(key.trim().to_owned()).or_insert(value);
        }
        i = next;
    }
    out
}

// ---- CEF ------------------------------------------------------------------------

/// Where each field sits in a CEF header, after the version has been split off.
///
/// Named rather than written as bare indices, because the first version of `cef` read
/// `SignatureID` as the event name and every CEF test said so. An off-by-one in a
/// positional format is invisible in review and obvious in a test.
mod cef_field {
    pub const VENDOR: usize = 0;
    pub const NAME: usize = 4;
    pub const SEVERITY: usize = 5;
    pub const EXTENSION: usize = 6;
    /// Vendor, Product, Version, `SignatureID`, Name, Severity, extension.
    pub const COUNT: usize = 7;
}


/// `CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|extension`
///
/// The header is positional and pipe-separated, and a pipe inside a field is escaped as
/// `\|`. Seven fields before the extension; fewer means this is not CEF, whatever it says
/// at the front.
fn cef(body: &str) -> Option<Parsed> {
    let rest = body.trim_start().strip_prefix("CEF:")?;
    // The version digit, then the header.
    let (_version, rest) = rest.split_once('|')?;

    let header = split_escaped(rest, cef_field::COUNT - 1)?;
    if header.len() < cef_field::COUNT {
        return None;
    }

    let vendor = header[cef_field::VENDOR].trim().to_owned();
    let name = header[cef_field::NAME].trim().to_owned();
    let extension = &header[cef_field::EXTENSION];

    let mut fields = pairs(extension);
    // The header's severity is the device's own, and CEF puts it where an extension key
    // cannot: position seven. Kept under a name the alias table knows.
    fields
        .entry("cef.severity".to_owned())
        .or_insert_with(|| header[cef_field::SEVERITY].trim().to_owned());

    Some(Parsed {
        shape: Shape::Cef,
        fields,
        vendor: (!vendor.is_empty()).then_some(vendor),
        name: (!name.is_empty()).then_some(name),
    })
}

/// Split on unescaped `|`, at most `limit` times, returning the pieces plus the remainder.
fn split_escaped(text: &str, limit: usize) -> Option<Vec<String>> {
    let mut out = Vec::with_capacity(limit + 1);
    let mut current = String::new();
    let mut escaped = false;

    for ch in text.chars() {
        if escaped {
            // `\|` is a literal pipe; any other escape keeps both characters, because
            // inventing an unescaping rule CEF does not have would corrupt values.
            if ch != '|' && ch != '\\' {
                current.push('\\');
            }
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '|' if out.len() < limit => {
                out.push(std::mem::take(&mut current));
            }
            _ => current.push(ch),
        }
    }
    out.push(current);
    (out.len() > limit).then_some(out)
}

// ---- JSON -----------------------------------------------------------------------

/// A JSON object as the whole body, read one level deep.
///
/// Hand-written rather than `serde_json`, and that is a real decision: this runs per log
/// line at ingest rate, it only needs the top level, and a full parse of a deeply nested
/// document to read six keys is work nobody asked for. It also means a body that is *not*
/// JSON costs one character to reject.
fn json(body: &str) -> Option<Parsed> {
    let text = body.trim();
    if !text.starts_with('{') || !text.ends_with('}') {
        return None;
    }
    let inner = &text[1..text.len() - 1];

    let mut fields = BTreeMap::new();
    let chars: Vec<char> = inner.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        // A key is a quoted string.
        while i < chars.len() && chars[i] != '"' {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let (key, next) = quoted(&chars, i)?;
        i = next;

        while i < chars.len() && chars[i] != ':' {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        i += 1;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }

        let (value, next) = match chars[i] {
            '"' => quoted(&chars, i)?,
            // A nested object or array is kept as text under its own key. A flattening
            // convention is a thing every consumer has to learn, and this product already
            // has one for RFC 5424 — a second would be a second thing to remember.
            '{' | '[' => balanced(&chars, i)?,
            _ => {
                let from = i;
                let end = (from..chars.len())
                    .find(|&n| chars[n] == ',')
                    .unwrap_or(chars.len());
                (chars[from..end].iter().collect::<String>().trim().to_owned(), end)
            }
        };
        i = next;

        if !key.is_empty() {
            fields.entry(key).or_insert(value);
        }

        while i < chars.len() && chars[i] != ',' {
            i += 1;
        }
        i += 1;
    }

    (fields.len() >= MIN_PAIRS).then_some(Parsed {
        shape: Shape::Json,
        fields,
        vendor: None,
        name: None,
    })
}

/// A quoted string starting at `at`, with `\"` honoured. Returns the contents and the index
/// after the closing quote.
fn quoted(chars: &[char], at: usize) -> Option<(String, usize)> {
    if chars.get(at) != Some(&'"') {
        return None;
    }
    let mut out = String::new();
    let mut i = at + 1;
    while i < chars.len() {
        match chars[i] {
            '\\' if i + 1 < chars.len() => {
                // Only the escapes JSON actually defines for a string's *content* that
                // matter here. `\n` and friends stay as written rather than being
                // interpreted: this value goes into an attribute, not onto a terminal.
                out.push(chars[i + 1]);
                i += 2;
            }
            '"' => return Some((out, i + 1)),
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    None
}

/// A balanced `{…}` or `[…]` starting at `at`, returned verbatim.
fn balanced(chars: &[char], at: usize) -> Option<(String, usize)> {
    let (open, close) = match chars.get(at)? {
        '{' => ('{', '}'),
        '[' => ('[', ']'),
        _ => return None,
    };
    let mut depth = 0usize;
    let mut in_string = false;
    let mut i = at;
    while i < chars.len() {
        match chars[i] {
            '\\' if in_string => i += 1,
            '"' => in_string = !in_string,
            c if c == open && !in_string => depth += 1,
            c if c == close && !in_string => {
                depth -= 1;
                if depth == 0 {
                    return Some((chars[at..=i].iter().collect(), i + 1));
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

// ---- RFC 5424 structured data ---------------------------------------------------

/// Structured data the syslog parser already flattened into attributes.
///
/// `uops_syslog` flattens `[id@32473 src="1.2.3.4"]` to `id@32473.src`. The last segment is
/// the field name; the prefix is the SD-ID, which is an enterprise number and means nothing
/// to this table.
fn structured_data(structured: &BTreeMap<String, String>) -> Option<Parsed> {
    let mut fields = BTreeMap::new();
    for (key, value) in structured {
        let name = key.rsplit('.').next().unwrap_or(key);
        if !name.is_empty() {
            fields.entry(name.to_owned()).or_insert_with(|| value.clone());
        }
    }
    (fields.len() >= MIN_PAIRS).then_some(Parsed {
        shape: Shape::StructuredData,
        fields,
        vendor: None,
        name: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none() -> BTreeMap<String, String> {
        BTreeMap::new()
    }

    #[test]
    fn the_number_of_shapes_is_a_decision() {
        // M11 §2.2: the count is the control. Adding a fifth grammar is a deliberate act
        // with a failing test attached, which is the whole defence against this file
        // becoming a vendor parser library.
        assert_eq!(
            SHAPES.len(),
            4,
            "a shape was added or removed. That is allowed — M11 §2.2 says four or five — \
             but it is a decision, and this test is where it gets made rather than \
             inherited"
        );
    }

    #[test]
    fn cef_is_tried_before_key_value() {
        // A CEF body's extension *is* the key=value grammar, so the other order would match
        // the extension and silently throw the header — vendor, product, event name — away.
        let cef_at = SHAPES.iter().position(|s| *s == Shape::Cef).unwrap();
        let kv_at = SHAPES.iter().position(|s| *s == Shape::KeyValue).unwrap();
        assert!(cef_at < kv_at);
    }

    // --- key=value ---

    #[test]
    fn a_firewall_body_becomes_its_fields() {
        let parsed = parse("src=10.0.0.5 dst=8.8.8.8 dpt=53 proto=UDP act=deny", &none())
            .expect("a key=value body");
        assert_eq!(parsed.shape, Shape::KeyValue);
        assert_eq!(parsed.fields.get("src").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(parsed.fields.get("dpt").map(String::as_str), Some("53"));
        assert_eq!(parsed.fields.get("act").map(String::as_str), Some("deny"));
    }

    #[test]
    fn a_quoted_value_may_contain_spaces() {
        let parsed = parse(
            r#"src=10.0.0.5 dst=10.0.0.9 msg="connection reset by peer" act=drop"#,
            &none(),
        )
        .expect("parsed");
        assert_eq!(
            parsed.fields.get("msg").map(String::as_str),
            Some("connection reset by peer")
        );
        assert_eq!(parsed.fields.get("act").map(String::as_str), Some("drop"));
    }

    #[test]
    fn a_key_starts_after_the_previous_space() {
        // `%ASA-6-302013: Built outbound TCP connection src=…` — the prose before the first
        // pair must not become part of a key.
        let parsed = parse(
            "Built outbound TCP connection src=10.0.0.5 dst=8.8.8.8 dpt=443",
            &none(),
        )
        .expect("parsed");
        assert!(parsed.fields.contains_key("src"), "{:?}", parsed.fields);
        assert!(!parsed.fields.keys().any(|k| k.contains(' ')));
    }

    #[test]
    fn an_english_sentence_with_one_equals_sign_is_not_a_structured_message() {
        // The failure this guards: treating prose as structured produces an event with one
        // field and no meaning, and something downstream then counts it.
        assert!(parse("Started service=sshd", &none()).is_none());
        assert!(parse("interface Gi0/1 changed state to down", &none()).is_none());
        assert!(parse("", &none()).is_none());
    }

    #[test]
    fn an_unterminated_quote_keeps_what_there_was() {
        // A truncated message is common. The value up to the cut is still a value, and
        // dropping the whole pair would lose the fields after it too.
        let parsed = parse(r#"src=1.1.1.1 dst=2.2.2.2 msg="cut off here"#, &none()).expect("parsed");
        assert_eq!(parsed.fields.get("msg").map(String::as_str), Some("cut off here"));
    }

    // --- CEF ---

    #[test]
    fn a_cef_message_yields_its_header_and_its_extension() {
        let parsed = parse(
            "CEF:0|Palo Alto Networks|PAN-OS|10.2|threat|Traffic Denied|5|src=10.0.0.5 \
             dst=203.0.113.9 dpt=445 act=deny",
            &none(),
        )
        .expect("a CEF body");
        assert_eq!(parsed.shape, Shape::Cef);
        assert_eq!(parsed.vendor.as_deref(), Some("Palo Alto Networks"));
        assert_eq!(parsed.name.as_deref(), Some("Traffic Denied"));
        assert_eq!(parsed.fields.get("src").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(parsed.fields.get("cef.severity").map(String::as_str), Some("5"));
    }

    #[test]
    fn an_escaped_pipe_stays_inside_its_header_field() {
        let parsed = parse(
            r"CEF:0|Acme|Box|1.0|100|Blocked \| by policy|7|src=1.1.1.1 dst=2.2.2.2 act=block",
            &none(),
        )
        .expect("parsed");
        assert_eq!(parsed.name.as_deref(), Some("Blocked | by policy"));
        assert_eq!(parsed.fields.get("act").map(String::as_str), Some("block"));
    }

    #[test]
    fn something_that_says_cef_and_is_not_is_refused() {
        // Fewer than the seven header fields the format defines. Producing a half-event
        // from it would be exactly the guess this module refuses.
        assert!(parse("CEF:0|Acme|Box", &none()).is_none());
        assert!(parse("CEF is a log format", &none()).is_none());
    }

    // --- JSON ---

    #[test]
    fn a_json_body_yields_its_top_level() {
        let parsed = parse(
            r#"{"src_ip":"10.0.0.5","dest_ip":"8.8.8.8","action":"allowed","port":443}"#,
            &none(),
        )
        .expect("a JSON body");
        assert_eq!(parsed.shape, Shape::Json);
        assert_eq!(parsed.fields.get("src_ip").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(parsed.fields.get("action").map(String::as_str), Some("allowed"));
        // A number is kept as the text it was. The attributes map is `Map(String, String)`
        // and inventing a numeric type here would have to be undone at the column.
        assert_eq!(parsed.fields.get("port").map(String::as_str), Some("443"));
    }

    #[test]
    fn a_nested_object_is_kept_as_text_under_its_own_key() {
        // Rather than flattened with an invented separator: a flattening convention is a
        // thing every consumer has to learn, and this product already has one for RFC 5424.
        let parsed = parse(
            r#"{"user":{"name":"alice","id":7},"action":"login","outcome":"success"}"#,
            &none(),
        )
        .expect("parsed");
        assert_eq!(
            parsed.fields.get("user").map(String::as_str),
            Some(r#"{"name":"alice","id":7}"#)
        );
        assert_eq!(parsed.fields.get("outcome").map(String::as_str), Some("success"));
    }

    #[test]
    fn an_escaped_quote_inside_a_json_string_survives() {
        let parsed = parse(
            r#"{"msg":"he said \"stop\"","action":"deny","src":"1.1.1.1"}"#,
            &none(),
        )
        .expect("parsed");
        assert_eq!(
            parsed.fields.get("msg").map(String::as_str),
            Some(r#"he said "stop""#)
        );
    }

    #[test]
    fn something_that_is_not_json_costs_one_character_to_reject() {
        assert!(parse("not json at all", &none()).is_none());
        assert!(parse("{unclosed", &none()).is_none());
    }

    // --- structured data ---

    #[test]
    fn rfc5424_structured_data_is_read_from_the_attributes() {
        // Parsed upstream by `uops-syslog`; listed as a shape because it is a grammar this
        // product reads, and leaving it out would make SHAPES a lie about what is understood.
        let sd: BTreeMap<String, String> = [
            ("fw@32473.src", "10.0.0.5"),
            ("fw@32473.dst", "8.8.8.8"),
            ("fw@32473.act", "deny"),
        ]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();

        let parsed = parse("some prose the device wrote", &sd).expect("structured data");
        assert_eq!(parsed.shape, Shape::StructuredData);
        assert_eq!(parsed.fields.get("src").map(String::as_str), Some("10.0.0.5"));
        assert_eq!(parsed.fields.get("act").map(String::as_str), Some("deny"));
    }

    #[test]
    fn a_body_that_parses_wins_over_structured_data() {
        // Both present: the body is what the device chose to say about this event, and the
        // structured data is usually the relay's. Order in SHAPES decides, and this pins it.
        let sd: BTreeMap<String, String> = [("x@1.a", "1"), ("x@1.b", "2"), ("x@1.c", "3")]
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        let parsed = parse("src=9.9.9.9 dst=8.8.8.8 act=allow", &sd).expect("parsed");
        assert_eq!(parsed.shape, Shape::KeyValue);
    }
}
