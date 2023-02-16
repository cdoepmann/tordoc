//! Tor consensus documents

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::prelude::*;
use std::net::Ipv4Addr;
use std::num::ParseIntError;
use std::path::Path;
use std::str::FromStr;

use super::meta;
use crate::descriptor::Descriptor;
use crate::error::{DocumentCombiningError, DocumentParseError, ErrorContext};
use meta::{Document, Fingerprint};

//
// External dependencies
//
use chrono::{offset::TimeZone, DateTime, Utc};
use derive_builder::Builder;
use regex::Regex;
use strum::{EnumString, EnumVariantNames, IntoStaticStr, VariantNames};

/// A relay flag in the consensus
#[derive(Debug, Clone, Copy, EnumString, EnumVariantNames, IntoStaticStr, PartialEq, Eq)]
pub enum Flag {
    Authority,
    BadExit,
    Exit,
    Fast,
    Guard,
    HSDir,
    Named,
    Unnamed,
    NoEdConsensus,
    Running,
    Stable,
    StaleDesc,
    Sybil,
    V2Dir,
    Valid,
}

impl Flag {
    pub fn known_flags_string() -> String {
        Flag::VARIANTS.join(" ")
    }
}

/// A Tor sub-protocol
#[derive(Debug, Clone, EnumString, IntoStaticStr, PartialEq, PartialOrd, Eq, Ord)]
pub enum Protocol {
    Cons,
    Desc,
    DirCache,
    FlowCtrl,
    HSDir,
    HSIntro,
    HSRend,
    Link,
    LinkAuth,
    Microdesc,
    Padding,
    Relay,
}

/// A range of supported protocol versions
#[derive(Debug, Clone)]
pub struct SupportedProtocolVersion {
    versions: Vec<u8>,
}

impl SupportedProtocolVersion {
    pub fn supports(&self, v: u8) -> bool {
        self.versions.contains(&v)
    }
}

impl fmt::Display for SupportedProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut last_version = None;
        let mut range_end = None;
        for v in self.versions.iter().copied() {
            match last_version {
                Some(last) => {
                    if v == last + 1 {
                        if range_end.is_none() {
                            write!(f, "-")?;
                        }
                        range_end = Some(v);
                    } else {
                        if let Some(x) = range_end.take() {
                            write!(f, "{}", x)?;
                        }
                        write!(f, ",{}", v)?;
                    }
                }
                None => {
                    // first element
                    write!(f, "{}", v)?;
                }
            }
            last_version = Some(v);
        }
        if let Some(x) = range_end.take() {
            write!(f, "{}", x)?;
        }

        Ok(())
    }
}

impl FromStr for SupportedProtocolVersion {
    type Err = DocumentParseError;

    /// Parse from "3" or "2-5".
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut versions = Vec::new();
        for component in s.split(',') {
            match component.split_once('-') {
                Some((min, max)) => {
                    let min = u8::from_str_radix(min, 10).context("protocol version (from)")?;
                    let max = u8::from_str_radix(max, 10).context("protocol version (to)")?;

                    for i in min..=max {
                        versions.push(i);
                    }
                }
                None => {
                    let elem = u8::from_str_radix(component, 10).context("protocol version")?;
                    versions.push(elem);
                }
            }
        }
        versions.sort_unstable();
        Ok(SupportedProtocolVersion { versions })
    }
}

/// Exit policy type
#[derive(Debug, Clone, Copy)]
pub enum ExitPolicyType {
    Accept,
    Reject,
}

/// Exit port entry
#[derive(Debug, Clone, Copy)]
pub enum ExitPolicyEntry {
    SinglePort(u16),
    PortRange { min: u16, max: u16 },
}

impl ExitPolicyEntry {
    pub fn matches_port(&self, port: u16) -> bool {
        match self {
            ExitPolicyEntry::SinglePort(a) => *a == port,
            ExitPolicyEntry::PortRange { min, max } => port >= *min && port <= *max,
        }
    }

    pub fn to_ports(&self) -> Vec<u16> {
        self.iter_ports().collect()
    }

    pub fn iter_ports(&self) -> impl Iterator<Item = u16> {
        match *self {
            ExitPolicyEntry::SinglePort(x) => x..=x,
            ExitPolicyEntry::PortRange { min, max } => min..=max,
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        match *self {
            ExitPolicyEntry::SinglePort(x) => x == port,
            ExitPolicyEntry::PortRange { min, max } => min <= port && port <= max,
        }
    }
}

impl FromStr for ExitPolicyEntry {
    type Err = DocumentParseError;

    /// Parse from "3" or "2-5".
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('-') {
            Some((min, max)) => Ok(ExitPolicyEntry::PortRange {
                min: u16::from_str_radix(min, 10).context("exit policy port (from)")?,
                max: u16::from_str_radix(max, 10).context("exit policy port (to)")?,
            }),
            None => Ok(ExitPolicyEntry::SinglePort(
                u16::from_str_radix(s, 10).context("exit policy port")?,
            )),
        }
        .map_err(
            |_: ParseIntError| DocumentParseError::InvalidExitPolicyEntry { raw: s.to_string() },
        )
    }
}

impl fmt::Display for ExitPolicyEntry {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ExitPolicyEntry::SinglePort(x) => {
                write!(f, "{}", x)?;
            }
            ExitPolicyEntry::PortRange { min: x, max: y } => {
                write!(f, "{}-{}", x, y)?;
            }
        }
        Ok(())
    }
}

/// A relay's condensed exit policy (ports for "most" target IP addresses)
#[derive(Debug, Clone)]
pub struct CondensedExitPolicy {
    pub policy_type: ExitPolicyType,
    pub entries: Vec<ExitPolicyEntry>,
}

impl CondensedExitPolicy {
    pub fn to_descriptor_lines(&self) -> Vec<String> {
        match self.policy_type {
            ExitPolicyType::Reject => {
                vec!["reject *:*".to_string()]
            }
            ExitPolicyType::Accept => {
                let mut lines = Vec::new();

                for entry in self.entries.iter() {
                    for port in entry.to_ports() {
                        lines.push(format!("accept *:{}", port));
                    }
                }
                lines.push("reject *:*".to_string());

                lines
            }
        }
    }

    pub fn allows_port(&self, port: u16) -> bool {
        match self.policy_type {
            ExitPolicyType::Reject => {
                return false;
            }
            ExitPolicyType::Accept => {
                for entry in self.entries.iter() {
                    if entry.contains(port) {
                        return true;
                    }
                }
                return false;
            }
        }
    }
}

impl FromStr for CondensedExitPolicy {
    type Err = DocumentParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (cmd, ports) = s
            .split_once(' ')
            .ok_or(DocumentParseError::MalformedExitPolicy)?;
        let policy_type = match cmd {
            "accept" => ExitPolicyType::Accept,
            "reject" => ExitPolicyType::Reject,
            _ => return Err(DocumentParseError::MalformedExitPolicy),
        };
        let entries = ports
            .split(',')
            .map(|x| x.parse::<ExitPolicyEntry>())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CondensedExitPolicy {
            policy_type,
            entries,
        })
    }
}

impl fmt::Display for CondensedExitPolicy {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{} {}",
            match self.policy_type {
                ExitPolicyType::Accept => "accept",
                ExitPolicyType::Reject => "reject",
            },
            self.entries
                .iter()
                .map(|x| x.to_string())
                .collect::<Vec<_>>()
                .join(",")
        )
        .unwrap();
        Ok(())
    }
}

/// A parsed consensus document ("network status").
#[derive(Debug)]
pub struct Consensus {
    pub valid_after: DateTime<Utc>,
    pub relays: Vec<Relay>,
    pub weights: BTreeMap<String, u64>,
}

/// A relay entry within the consensus, containing only these sparse information
/// instead of the full server descriptor
#[derive(Debug, Clone, Builder)]
#[builder(private)]
pub struct Relay {
    pub nickname: String,
    pub fingerprint: Fingerprint,
    pub digest: Fingerprint,
    pub published: DateTime<Utc>,
    pub address: Ipv4Addr,
    pub or_port: u16,
    pub dir_port: Option<u16>,
    pub flags: Vec<Flag>,
    pub version_line: String,
    pub protocols: BTreeMap<Protocol, SupportedProtocolVersion>,
    pub exit_policy: CondensedExitPolicy,
    pub bandwidth_weight: u64,
}

///

impl Consensus {
    /// Parse a consensus document from raw text.
    pub fn from_str(text: impl AsRef<str>) -> Result<Consensus, DocumentParseError> {
        let doc = Document::parse_single(text.as_ref())?;
        Self::from_doc(doc)
    }
    /// Parse a consensus document from an already-parsed Tor meta document
    pub(crate) fn from_doc(doc: Document) -> Result<Consensus, DocumentParseError> {
        // the current relay we're constructing
        let mut relay: Option<RelayBuilder> = None;

        // collected relays
        let mut relays: Vec<Relay> = Vec::new();

        // collect relays
        for item in doc.items.iter().skip_while(|&x| x.keyword != "r") {
            match item.keyword {
                "r" => {
                    // if another relay was in process, finish it
                    if let Some(old) = relay.take() {
                        relays.push(
                            old.build()
                                .map_err(|err| DocumentParseError::Incomplete(Box::new(err)))?,
                        );
                    }
                    // start a new relay
                    relay = Some(RelayBuilder::default());
                    let relay = relay.as_mut().unwrap();

                    // parse entries
                    let splits = item.split_arguments()?;
                    match splits[..] {
                        [nickname, identity, digest, published_1, published_2, ip, or_port, dir_port, ..] =>
                        {
                            relay.nickname(nickname.to_string());
                            relay.fingerprint(Fingerprint::from_str_b64(identity)?);
                            relay.digest(Fingerprint::from_str_b64(digest)?);
                            relay.published(Utc.datetime_from_str(
                                &format!("{published_1} {published_2}"),
                                "%Y-%m-%d %H:%M:%S",
                            )?);
                            let address = Ipv4Addr::from_str(ip).map_err(|_| {
                                DocumentParseError::InvalidIpAddress(ip.to_string())
                            })?;
                            relay.address(address);
                            relay.or_port(u16::from_str_radix(or_port, 10).context("OR port")?);
                            relay.dir_port(
                                match u16::from_str_radix(dir_port, 10).context("dir port")? {
                                    0 => None,
                                    x => Some(x),
                                },
                            );
                        }
                        _ => {
                            return Err(DocumentParseError::ItemArgumentsMissing {
                                keyword: item.keyword.to_string(),
                            })
                        }
                    }
                }
                "s" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;

                    // parse flags
                    let splits = item.split_arguments()?;
                    let flags: Vec<Flag> = splits
                        .iter()
                        .filter(|x| x.trim_start().len() > 0)
                        .map(|x| {
                            x.parse::<Flag>()
                                .map_err(|_| DocumentParseError::UnknownFlag {
                                    flag: x.to_string(),
                                })
                        })
                        .collect::<Result<Vec<_>, _>>()?;
                    relay.flags(flags);
                }
                "v" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;
                    relay.version_line(item.arguments.unwrap_or("").to_string());
                }
                "pr" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;
                    // parse flags
                    let mut protocols = BTreeMap::new();
                    let splits = item.split_arguments()?;
                    for split in splits.iter() {
                        if split.trim_start().len() == 0 {
                            continue;
                        }
                        let (left, right) = split
                            .split_once('=')
                            .ok_or(DocumentParseError::InvalidArgumentDict)?;
                        let prot = left.parse::<Protocol>().map_err(|_| {
                            DocumentParseError::UnknownProtocol {
                                protocol: left.to_string(),
                            }
                        })?;
                        let vers = right.parse::<SupportedProtocolVersion>().map_err(|_| {
                            DocumentParseError::InvalidProtocolVersion {
                                raw: right.to_string(),
                            }
                        })?;
                        protocols.insert(prot, vers);
                    }
                    relay.protocols(protocols);
                }
                "p" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;

                    // parse policy
                    relay.exit_policy(item.get_argument()?.parse::<CondensedExitPolicy>()?);
                }
                "w" => {
                    // get builder
                    let relay = relay
                        .as_mut()
                        .ok_or(DocumentParseError::UnexpectedKeyword {
                            keyword: item.keyword.to_string(),
                        })?;
                    // parse bandwidth weight
                    if !item.get_argument()?.starts_with("Bandwidth=") {
                        return Err(DocumentParseError::InvalidBandwidthWeight);
                    }
                    let arguments = item.split_arguments()?;
                    for arg in arguments.iter() {
                        let (k, v) = arg
                            .split_once('=')
                            .ok_or(DocumentParseError::InvalidBandwidthWeight)?;
                        match k {
                            "Bandwidth" => {
                                relay.bandwidth_weight(
                                    u64::from_str_radix(v, 10)
                                        .map_err(|_| DocumentParseError::InvalidBandwidthWeight)?,
                                );
                            }
                            _ => {}
                        }
                    }
                }
                "a" => {
                    // IPv6 addresses, not implemented
                    // TODO
                }
                _ => {
                    if let Some(last) = relay.take() {
                        relays.push(
                            last.build()
                                .map_err(|err| DocumentParseError::Incomplete(Box::new(err)))?,
                        );
                    }
                    break;
                }
            }
        }

        // collect weights
        let weights = {
            let item = doc
                .items
                .iter()
                .skip_while(|&x| x.keyword != "bandwidth-weights")
                .next()
                .ok_or(DocumentParseError::ConsensusWeightsMissing)?;
            let mut weights = BTreeMap::new();

            let args = item.split_arguments()?;
            for arg in args.iter() {
                let (k, v) = arg
                    .split_once('=')
                    .ok_or(DocumentParseError::MalformedConsensusWeights)?;
                let v = u64::from_str_radix(v, 10)
                    .map_err(|_| DocumentParseError::MalformedConsensusWeights)?;
                weights.insert(k.to_string(), v);
            }

            weights
        };

        // collect valid-after
        let valid_after = {
            let item = doc
                .items
                .iter()
                .skip_while(|&x| x.keyword != "valid-after")
                .next()
                .ok_or(DocumentParseError::ValidAfterMissing)?;
            let arg = item.get_argument()?;
            Utc.datetime_from_str(arg, "%Y-%m-%d %H:%M:%S")?
        };
        // return everything
        Ok(Consensus {
            relays,
            weights,
            valid_after,
        })
    }

    /// Retrieve the descriptors refererenced in this consensus from local files.
    ///
    /// This is a convenience method to automatically retrieve and parse all
    /// the descriptors referenced in this consensus.
    /// This assumes that all the files are organized in a folder hierarchy
    /// as created by extracting the files from [Tor Metrics/collecTor](https://collector.torproject.org/archive/relay-descriptors/).
    ///
    /// Since the consensus does not know its on-disk file path,
    /// it has to be provided as a parameter here.
    /// The descriptors are looked up relative to this location.
    pub fn retrieve_descriptors(
        &self,
        consensus_path: impl AsRef<Path>,
    ) -> Result<Vec<Descriptor>, DocumentCombiningError> {
        let consensus_path = consensus_path.as_ref();
        // get year and month
        let fname_regex = Regex::new(r"^(\d{4})-(\d{2})-(\d{2})-").unwrap();
        let fname_match = fname_regex
            .captures(
                consensus_path
                    .file_name()
                    .ok_or(DocumentCombiningError::InvalidFolderStructure)?
                    .to_str()
                    .ok_or(DocumentCombiningError::InvalidFolderStructure)?,
            )
            .ok_or(DocumentCombiningError::InvalidFolderStructure)?;
        let this_year: u32 = fname_match.get(1).unwrap().as_str().parse().unwrap();
        let this_month: u32 = fname_match.get(2).unwrap().as_str().parse().unwrap();

        let (previous_year, previous_month) = if this_month == 1 {
            (this_year - 1, 12)
        } else {
            (this_year, this_month - 1)
        };

        // find the corresponding descriptor folders (current month and the one before)
        let current_desc = consensus_path
            .parent()
            .ok_or(DocumentCombiningError::InvalidFolderStructure)?
            .join(format!(
                "../../server-descriptors-{:04}-{:02}/",
                this_year, this_month
            ));
        if !current_desc.exists() {
            return Err(DocumentCombiningError::InvalidFolderStructure);
        }
        let previous_desc = consensus_path
            .parent()
            .ok_or(DocumentCombiningError::InvalidFolderStructure)?
            .join(format!(
                "../../server-descriptors-{:04}-{:02}/",
                previous_year, previous_month
            ));

        // Lookup the descriptors
        let mut descriptors = Vec::new();
        for relay in self.relays.iter() {
            let digest = format!("{}", relay.digest);
            let first_char = digest.chars().next().unwrap();
            let second_char = digest.chars().skip(1).next().unwrap();

            let subpath = format!("{}/{}/{}", first_char, second_char, digest);
            let current_path = current_desc.join(&subpath);
            let previous_path = previous_desc.join(&subpath);

            let desc_path = if current_path.exists() {
                current_path
            } else if previous_path.exists() {
                previous_path
            } else {
                return Err(DocumentCombiningError::MissingDescriptor {
                    digest: relay.digest.clone(),
                });
            };

            let mut raw = String::new();
            let mut file = File::open(desc_path).unwrap();
            file.read_to_string(&mut raw).unwrap();
            descriptors.push(Descriptor::from_str(raw)?);
        }

        Ok(descriptors)
    }
}
