//! Tor server descriptor documents

use std::net::IpAddr;
use std::str::FromStr;

use crate::error::{DocumentParseError, ErrorContext};

use super::meta;
use meta::get_raw_content_between_bytes;
use meta::{Document, Fingerprint};

mod exit;
pub use exit::{
    DescriptorExitPolicy, DescriptorExitPolicyIPv6, DescriptorExitPolicyRule, ExitPolicyAddress,
    ExitPolicyPort, ExitPolicyType, ExitPortRange,
};

//
// External dependencies
//
use chrono::{offset::TimeZone, DateTime, Utc};
use sha1::{Digest, Sha1};

#[derive(Debug, Clone)]
pub enum FamilyMember {
    Fingerprint(Fingerprint),
    Nickname(String),
}

#[derive(Debug, Clone)]
pub struct OrAddress {
    pub ip: IpAddr,
    pub port: u16,
}

/// A relay server descriptor.
///
/// We here only focus on pieces of information that aren't present in the
/// consensus yet.
#[derive(Debug, Clone)]
pub struct Descriptor {
    pub nickname: Option<String>,
    pub fingerprint: Option<Fingerprint>,
    pub digest: Option<Fingerprint>,
    pub published: Option<DateTime<Utc>>,
    pub or_addresses: Option<Vec<OrAddress>>,
    pub family_members: Option<Vec<FamilyMember>>,
    pub bandwidth_avg: Option<u64>,
    pub bandwidth_burst: Option<u64>,
    pub bandwidth_observed: Option<u64>,
    pub exit_policy: Option<DescriptorExitPolicy>,
    pub exit_policies_ipv6: Option<DescriptorExitPolicyIPv6>,
}

impl Descriptor {
    fn new() -> Descriptor {
        Descriptor {
            nickname: None,
            fingerprint: None,
            digest: None,
            published: None,
            or_addresses: None,
            family_members: None,
            bandwidth_avg: None,
            bandwidth_burst: None,
            bandwidth_observed: None,
            exit_policy: None,
            exit_policies_ipv6: None,
        }
    }
}

impl Descriptor {
    fn add_or_address(&mut self, or: OrAddress) {
        self.or_addresses.get_or_insert_with(Vec::new).push(or);
    }

    fn add_exit_policy_rule(&mut self, epr: DescriptorExitPolicyRule) {
        self.exit_policy
            .get_or_insert_with(DescriptorExitPolicy::new)
            .add_rule(epr);
    }
}

impl Descriptor {
    /// Parse a descriptor document from raw text.
    pub fn from_str(text: impl AsRef<str>) -> Result<Descriptor, DocumentParseError> {
        let doc = Document::parse_single(text.as_ref())?;
        Self::from_doc(doc)
    }

    /// Parse several descriptor documents all contained in a raw text.
    pub fn many_from_str(text: impl AsRef<str>) -> Result<Vec<Descriptor>, DocumentParseError> {
        let docs = Document::parse_many(text.as_ref())?;
        let descriptors = docs
            .into_iter()
            .map(Descriptor::from_doc)
            .collect::<Result<_, _>>()?;
        Ok(descriptors)
    }

    /// Parse a descriptor document from raw bytes.
    ///
    /// In contrast to [Descriptor::from_str], this function can also handle inputs with
    /// invalid UTF-8. In this case, the descriptor's digest is calculated from
    /// the original, non-UTF-8 content. Afterwards, the contents are converted
    /// to UTF-8 in a lossy way. Therefore, later re-computation of the digest
    /// (even if not mutating its content!) will yield a different result.
    /// Consequently, this input method may be **lossy**.
    pub fn from_bytes_lossy(bytes: impl AsRef<[u8]>) -> Result<Descriptor, DocumentParseError> {
        let bytes = bytes.as_ref();

        // Compute digest before converting to UTF-8
        let digest = digest_from_raw(get_raw_content_between_bytes(
            bytes,
            b"router",
            b"\nrouter-signature\n",
        )?);

        // Parse descriptor lossily
        let lossy_text = String::from_utf8_lossy(bytes);
        let mut descriptor = Descriptor::from_str(lossy_text)?;

        // Override digest
        descriptor.digest = Some(digest);

        Ok(descriptor)
    }

    /// Parse a descriptor document from an already-parsed Tor meta document
    pub(crate) fn from_doc(doc: Document) -> Result<Descriptor, DocumentParseError> {
        let mut descriptor = Descriptor::new();

        // compute digest
        descriptor.digest = Some(digest_from_raw(
            doc.get_raw_content_between("router", "\nrouter-signature\n")?,
        ));

        for item in doc.items.iter() {
            match item.keyword {
                "router" => {
                    let splits = item.split_arguments()?;
                    match splits[..] {
                        // nickname address ORPort SOCKSPort DirPort
                        [nickname, ip, or_port, _socks_port, _dir_port, ..] => {
                            descriptor.nickname = Some(nickname.to_string());

                            let ip = IpAddr::from_str(ip).map_err(|_| {
                                DocumentParseError::InvalidIpAddress(ip.to_string())
                            })?;
                            let or_address = OrAddress {
                                ip: ip,
                                port: or_port.parse::<u16>().context("OR port (descriptor)")?,
                            };

                            descriptor.add_or_address(or_address);
                        }
                        _ => {
                            return Err(DocumentParseError::ItemArgumentsMissing {
                                keyword: item.keyword.to_string(),
                            })
                        }
                    }
                }
                "fingerprint" => {
                    let arg = item.get_argument()?;
                    descriptor.fingerprint = Some(Fingerprint::from_str_hex(arg)?);
                }
                "opt" => {
                    let arg = item.get_argument()?;
                    if arg.starts_with("fingerprint ") {
                        descriptor.fingerprint =
                            Some(Fingerprint::from_str_hex(&arg["fingerprint ".len()..])?);
                    }
                }
                "family" => {
                    let args = item.split_arguments()?;
                    let family_members: Vec<FamilyMember> = args
                        .iter()
                        .map(|x| {
                            if x.starts_with('$') {
                                // if present, ignore everything starting from an "="
                                let fp_raw = match x.split_once(&['=', '~']) {
                                    Some((before, _after)) => &before[1..],
                                    None => &x[1..],
                                };

                                Ok(FamilyMember::Fingerprint(Fingerprint::from_str_hex(
                                    fp_raw,
                                )?))
                            } else {
                                Ok(FamilyMember::Nickname(x.to_string()))
                            }
                        })
                        .collect::<Result<Vec<FamilyMember>, DocumentParseError>>()?;
                    descriptor.family_members = Some(family_members);
                }
                "published" => {
                    let arg = item.get_argument()?;
                    descriptor.published = Some(Utc.datetime_from_str(arg, "%Y-%m-%d %H:%M:%S")?);
                }
                "bandwidth" => {
                    let splits = item.split_arguments()?;
                    match splits[..] {
                        // bandwidth-avg bandwidth-burst bandwidth-observed
                        [bandwidth_avg, bandwidth_burst, bandwidth_observed, ..] => {
                            descriptor.bandwidth_avg = Some(
                                u64::from_str_radix(bandwidth_avg, 10)
                                    .context("bw avg (descriptor)")?,
                            );
                            descriptor.bandwidth_burst = Some(
                                u64::from_str_radix(bandwidth_burst, 10)
                                    .context("bw burst (descriptor)")?,
                            );
                            descriptor.bandwidth_observed = Some(
                                u64::from_str_radix(bandwidth_observed, 10)
                                    .context("bw observed (descriptor)")?,
                            );
                        }
                        _ => {
                            return Err(DocumentParseError::ItemArgumentsMissing {
                                keyword: item.keyword.to_string(),
                            })
                        }
                    }
                }
                "or-address" => {
                    let arg = item.get_argument()?;
                    let arg_split = arg.split(']').collect::<Vec<&str>>();
                    match arg_split[..] {
                        // IPv6
                        [ip_str, port_str, ..] => {
                            let ip = IpAddr::from_str(&ip_str[1..]).map_err(|_| {
                                DocumentParseError::InvalidIpAddress(ip_str.to_string())
                            })?;
                            let or_address = OrAddress {
                                ip: ip,
                                port: port_str[1..]
                                    .parse::<u16>()
                                    .context("OR-address port IPv6 (descriptor)")?,
                            };
                            descriptor.add_or_address(or_address);
                        }
                        // IPv4
                        [ip_and_port_str] => {
                            let split = ip_and_port_str.split(':').collect::<Vec<&str>>();
                            match split[..] {
                                [ip_str, port_str, ..] => {
                                    let ip = IpAddr::from_str(&ip_str).map_err(|_| {
                                        DocumentParseError::InvalidIpAddress(ip_str.to_string())
                                    })?;
                                    let or_address = OrAddress {
                                        ip: ip,
                                        port: port_str
                                            .parse::<u16>()
                                            .context("OR-address port IPv4 (descriptor)")?,
                                    };
                                    descriptor.add_or_address(or_address);
                                }
                                _ => return Err(DocumentParseError::args_missing(item.keyword)),
                            }
                        }

                        _ => return Err(DocumentParseError::args_missing(item.keyword)),
                    }
                }
                "accept" => {
                    exit::parse_kw_accept(&mut descriptor, item)?;
                }
                "reject" => {
                    exit::parse_kw_reject(&mut descriptor, item)?;
                }

                "ipv6-policy" => {
                    exit::parse_kw_ipv6_policy(&mut descriptor, item)?;
                }
                _ => {}
            }
        }

        Ok(descriptor)
    }
}

/// Compute a descriptor's digest given the extracted raw content
pub fn digest_from_raw<R: AsRef<[u8]>>(raw: R) -> Fingerprint {
    let raw = raw.as_ref();
    let mut hasher = Sha1::new();
    hasher.update(raw);
    let result = hasher.finalize();
    Fingerprint::from_u8(&result)
}
