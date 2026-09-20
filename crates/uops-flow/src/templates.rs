//! What a collector remembers about the exporters talking to it.
//!
//! `NetFlow` v9 and IPFIX both send the layout separately from the data, and both make
//! the reader keep it. The shapes on the wire differ — IPFIX counts fields where v9
//! counts bytes, and IPFIX has variable-length fields where v9 has none — but what is
//! *remembered* is the same thing, so it is remembered in one place.
//!
//! # The key includes the protocol
//!
//! `docs/M7-flow.md` §2.2 requires `(exporter, observation domain, template ID)`, for the
//! reason that template IDs start at 256 on every exporter. The protocol is a fourth
//! component, and it is there for exactly the same reason one step further out: an
//! exporter mid-migration sends v9 and IPFIX at once, both from domain 0, both numbering
//! templates from 256. Without the protocol in the key one overwrites the other, and the
//! symptom is the same quiet one — fields of the right width holding the wrong values.

use std::collections::HashMap;
use std::net::IpAddr;

/// Which protocol's template space a template belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Protocol {
    NetFlow9,
    Ipfix,
}

/// Everything that identifies whose template this is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Source {
    pub exporter: IpAddr,
    pub protocol: Protocol,
    /// v9 calls it the source id; IPFIX calls it the observation domain. Same thing.
    pub domain: u32,
}

/// How much an exporter may make this process remember.
///
/// Bounded because the input is unauthenticated UDP: without limits, anything that can
/// reach the port can make the collector allocate by inventing exporters, template ids or
/// sampler ids.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Distinct sources — `(exporter, protocol, domain)` triples.
    pub max_sources: usize,
    /// Templates held for any one source.
    pub max_templates_per_source: usize,
    /// Distinct samplers remembered for any one source.
    pub max_samplers_per_source: usize,
}

impl Default for Limits {
    fn default() -> Self {
        // Room for a large estate — a thousand sources, each with a handful of templates
        // and headroom for re-registration — and still a bound a hostile sender cannot
        // walk past.
        Self {
            max_sources: 1024,
            max_templates_per_source: 64,
            max_samplers_per_source: 32,
        }
    }
}

/// One field, as a template declares it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Field {
    /// The information element identifier.
    pub kind: u16,
    /// Width in bytes. Meaningless when `variable` — the record carries the length.
    pub len: usize,
    /// IPFIX only: the length is in the record rather than the template. RFC 7011 §7.
    ///
    /// A flag rather than a sentinel length, because 65 535 is a legal fixed width in v9
    /// and reading one as the other is the kind of mistake this crate exists to avoid.
    pub variable: bool,
    /// IPFIX only: `kind` is a vendor's number, not IANA's.
    ///
    /// The two spaces overlap completely — enterprise 9's element 8 has nothing to do
    /// with `sourceIPv4Address` — so a decoder that forgets this reads a vendor's private
    /// value as whatever IANA happens to call that number. The bytes still have to be
    /// stepped over, which is why the field is kept rather than dropped at parse time.
    pub enterprise: bool,
}

/// What the records laid out by a template contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// Traffic.
    Data,
    /// The exporter's own configuration — which sampler runs at which interval.
    Options,
}

/// A layout for records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub fields: Vec<Field>,
    /// Bytes per record, when every field is fixed width.
    ///
    /// `None` when any field is variable-length, and the difference decides how a data
    /// set is read: a fixed template's records can be counted by division, a variable
    /// one's have to be walked one at a time because only the record says where the next
    /// begins.
    pub fixed_len: Option<usize>,
    pub kind: Kind,
}

impl Template {
    /// Build one, refusing the declarations that cannot be used.
    ///
    /// `None` when there are no fields, or when a fixed-width template totals zero bytes.
    /// The second is the one that matters: a data set's record count is its length
    /// divided by the record width, so a template of "one field, zero bytes wide" means a
    /// set holds infinitely many records and the collector never returns.
    #[must_use]
    pub fn new(fields: Vec<Field>, kind: Kind) -> Option<Self> {
        if fields.is_empty() {
            return None;
        }

        let fixed_len = if fields.iter().any(|f| f.variable) {
            None
        } else {
            let total: usize = fields.iter().map(|f| f.len).sum();
            if total == 0 {
                return None;
            }
            Some(total)
        };

        Some(Self {
            fields,
            fixed_len,
            kind,
        })
    }

    /// Walk one record, handing each field and its bytes to `visit`.
    ///
    /// The whole [`Field`] rather than its identifier alone, so that a caller cannot
    /// match on `kind` without having had the chance to notice [`Field::enterprise`].
    ///
    /// Returns how many bytes the record occupied, or `None` when it runs past the end of
    /// `buf` — which is a truncated set rather than a reason to panic.
    ///
    /// # Variable-length fields
    ///
    /// RFC 7011 §7: the field begins with a one-byte length, and if that byte is 255 the
    /// *real* length is the next two bytes. Both forms are read here, and both are
    /// checked against what actually arrived — a declared length is attacker-controlled
    /// input, and this is the acceptance criterion about one running past the end of the
    /// packet.
    pub fn walk(&self, buf: &[u8], mut visit: impl FnMut(&Field, &[u8])) -> Option<usize> {
        let mut at = 0usize;

        for field in &self.fields {
            let len = if field.variable {
                let first = *buf.get(at)?;
                at += 1;
                if first == 255 {
                    let hi = u16::from(*buf.get(at)?);
                    let lo = u16::from(*buf.get(at + 1)?);
                    at += 2;
                    usize::from((hi << 8) | lo)
                } else {
                    usize::from(first)
                }
            } else {
                field.len
            };

            let end = at.checked_add(len)?;
            let slice = buf.get(at..end)?;
            visit(field, slice);
            at = end;
        }

        Some(at)
    }
}

/// What an exporter said about its own sampling.
///
/// Held per source, because a sampler id is a number the exporter chose and means nothing
/// outside it.
#[derive(Clone, Debug, Default)]
pub struct Samplers {
    by_id: HashMap<u32, u32>,
    /// A rate declared with no sampler id, applying to everything the exporter sends.
    everything: Option<u32>,
}

impl Samplers {
    /// The rate for a record, which may or may not name a sampler.
    #[must_use]
    pub fn rate(&self, sampler: Option<u32>) -> Option<u32> {
        sampler
            .and_then(|id| self.by_id.get(&id).copied())
            .or(self.everything)
    }
}

/// Everything this collector has learned from the exporters talking to it.
///
/// Held across datagrams and deliberately *not* persisted: the gap after a restart is
/// inherent to the protocol, and it is reported rather than papered over.
#[derive(Debug)]
pub struct Learned {
    templates: HashMap<Source, HashMap<u16, Template>>,
    samplers: HashMap<Source, Samplers>,
    limits: Limits,
}

impl Default for Learned {
    fn default() -> Self {
        Self::new(Limits::default())
    }
}

impl Learned {
    #[must_use]
    pub fn new(limits: Limits) -> Self {
        Self {
            templates: HashMap::new(),
            samplers: HashMap::new(),
            limits,
        }
    }

    /// How many templates are held, across every source.
    #[must_use]
    pub fn len(&self) -> usize {
        self.templates.values().map(HashMap::len).sum()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    #[must_use]
    pub fn get(&self, source: Source, id: u16) -> Option<&Template> {
        self.templates.get(&source)?.get(&id)
    }

    #[must_use]
    pub fn samplers(&self, source: Source) -> Option<&Samplers> {
        self.samplers.get(&source)
    }

    /// Learn a template. `false` when a limit refused it.
    ///
    /// A template already held is *replaced*, and replacing never counts against the
    /// limit — an exporter re-registering the same id is the normal case, not growth. A
    /// redefinition is accepted because the protocol offers no way to reject one; §2.2
    /// records why the data records racing it cannot be rescued.
    pub fn learn(&mut self, source: Source, id: u16, template: Template) -> bool {
        if !self.templates.contains_key(&source) && self.templates.len() >= self.limits.max_sources
        {
            return false;
        }

        let slot = self.templates.entry(source).or_default();
        if !slot.contains_key(&id) && slot.len() >= self.limits.max_templates_per_source {
            // Refused rather than evicted. Evicting to make room means dropping whichever
            // exporter is quietest, which is the one nobody notices has gone missing.
            return false;
        }

        slot.insert(id, template);
        true
    }

    /// Remember what an options record said about a sampler.
    ///
    /// Bounded like the templates are. A sampler already known is updated, which does not
    /// count against the limit — an exporter re-announcing its configuration is normal.
    pub fn learn_sampler(&mut self, source: Source, sampler: Option<u32>, interval: u32) {
        if !self.samplers.contains_key(&source) && self.samplers.len() >= self.limits.max_sources {
            return;
        }

        let slot = self.samplers.entry(source).or_default();
        match sampler {
            Some(id) => {
                if !slot.by_id.contains_key(&id)
                    && slot.by_id.len() >= self.limits.max_samplers_per_source
                {
                    return;
                }
                slot.by_id.insert(id, interval);
            }
            None => slot.everything = Some(interval),
        }
    }
}
