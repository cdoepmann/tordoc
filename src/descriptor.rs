//! Tor server descriptor documents

use std::net::IpAddr;
use std::str::FromStr;

use crate::error::DocumentParseError;

use super::meta;
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
use derive_builder::Builder;
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
#[derive(Debug, Clone, Builder)]
#[builder(private)]
pub struct Descriptor {
    pub nickname: String,
    pub fingerprint: Fingerprint,
    pub digest: Fingerprint,
    pub published: DateTime<Utc>,
    #[builder(setter(custom))]
    pub or_addresses: Vec<OrAddress>,
    #[builder(default)]
    pub family_members: Vec<FamilyMember>,
    pub bandwidth_avg: u64,
    pub bandwidth_burst: u64,
    pub bandwidth_observed: u64,
    pub exit_policy: DescriptorExitPolicy,
    #[builder(default)]
    pub exit_policies_ipv6: DescriptorExitPolicyIPv6,
}

impl DescriptorBuilder {
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

    /// Parse a descriptor document from an already-parsed Tor meta document
    pub(crate) fn from_doc(doc: Document) -> Result<Descriptor, DocumentParseError> {
        let mut builder = DescriptorBuilder::default();

        // compute digest
        builder.digest(digest_from_raw(
            doc.get_raw_content_between("router", "\nrouter-signature\n")?,
        ));

        for item in doc.items.iter() {
            match item.keyword {
                "router" => {
                    let splits = item.split_arguments()?;
                    match splits[..] {
                        // nickname address ORPort SOCKSPort DirPort
                        [nickname, ip, or_port, _socks_port, _dir_port, ..] => {
                            builder.nickname(nickname.to_string());

                            let ip = IpAddr::from_str(ip).map_err(|_| {
                                DocumentParseError::InvalidIpAddress(ip.to_string())
                            })?;
                            let or_address = OrAddress {
                                ip: ip,
                                port: or_port.parse::<u16>()?,
                            };

                            builder.add_or_address(or_address);
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
                    builder.fingerprint(Fingerprint::from_str_hex(arg)?);
                }
                "family" => {
                    let args = item.split_arguments()?;
                    let family_members: Vec<FamilyMember> = args
                        .iter()
                        .map(|x| {
                            if x.starts_with('$') {
                                Ok(FamilyMember::Fingerprint(Fingerprint::from_str_hex(
                                    &x[1..],
                                )?))
                            } else {
                                Ok(FamilyMember::Nickname(x.to_string()))
                            }
                        })
                        .collect::<Result<Vec<FamilyMember>, DocumentParseError>>()?;
                    builder.family_members(family_members);
                }
                "published" => {
                    let arg = item.get_argument()?;
                    builder.published(Utc.datetime_from_str(arg, "%Y-%m-%d %H:%M:%S")?);
                }
                "bandwidth" => {
                    let splits = item.split_arguments()?;
                    match splits[..] {
                        // bandwidth-avg bandwidth-burst bandwidth-observed
                        [bandwidth_avg, bandwidth_burst, bandwidth_observed, ..] => {
                            builder.bandwidth_avg(u64::from_str_radix(bandwidth_avg, 10)?);
                            builder.bandwidth_burst(u64::from_str_radix(bandwidth_burst, 10)?);
                            builder
                                .bandwidth_observed(u64::from_str_radix(bandwidth_observed, 10)?);
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
                                port: port_str[1..].parse::<u16>()?,
                            };
                            builder.add_or_address(or_address);
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
                                        port: port_str.parse::<u16>()?,
                                    };
                                    builder.add_or_address(or_address);
                                }
                                _ => return Err(DocumentParseError::args_missing(item.keyword)),
                            }
                        }

                        _ => return Err(DocumentParseError::args_missing(item.keyword)),
                    }
                }
                "accept" => {
                    exit::parse_kw_accept(&mut builder, item)?;
                }
                "reject" => {
                    exit::parse_kw_reject(&mut builder, item)?;
                }

                "ipv6-policy" => {
                    exit::parse_kw_ipv6_policy(&mut builder, item)?;
                }
                _ => {}
            }
        }

        Ok(builder
            .build()
            .map_err(|e| DocumentParseError::Incomplete(Box::new(e)))?)
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
