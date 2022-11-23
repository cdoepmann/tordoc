//! Submodule bundling all code for exit poliy parsing in descriptors

use std::net::IpAddr;
use std::str::FromStr;

use crate::error::DocumentParseError;

use super::meta::Item;
use super::DescriptorBuilder;

use ipnet::IpNet;

#[derive(PartialEq, Debug, Clone)]
pub enum ExitPolicyAddress {
    Wildcard,
    Address(IpNet),
}

impl ExitPolicyAddress {
    fn to_string(&self) -> String {
        match self {
            ExitPolicyAddress::Wildcard => String::from("*"),
            ExitPolicyAddress::Address(addr) => addr.to_string(),
        }
    }
}
#[derive(PartialEq, Debug, Clone)]
pub enum ExitPortRange<T> {
    Single(T),
    Interval(T, T),
}
impl ExitPortRange<u16> {
    fn to_string(&self) -> String {
        match self {
            ExitPortRange::Single(num) => num.to_string(),
            ExitPortRange::Interval(num1, num2) => {
                num1.to_string() + " - " + num2.to_string().as_str()
            }
        }
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum ExitPolicyType {
    Accept,
    Reject,
}
impl ExitPolicyType {
    fn to_string(&self) -> String {
        match self {
            ExitPolicyType::Accept => String::from("accept"),
            ExitPolicyType::Reject => String::from("reject"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ExitPolicyPort {
    Wildcard,
    Port(ExitPortRange<u16>),
}

#[derive(Debug, Clone)]
pub struct DescriptorExitPolicyRule {
    pub ep_type: ExitPolicyType,
    pub address: ExitPolicyAddress,
    pub port: ExitPolicyPort,
}
impl ExitPolicyPort {
    fn to_string(&self) -> String {
        match self {
            ExitPolicyPort::Wildcard => String::from("*"),
            ExitPolicyPort::Port(port) => port.to_string(),
        }
    }

    pub fn contains(&self, port: u16) -> bool {
        match self {
            ExitPolicyPort::Wildcard => true,
            ExitPolicyPort::Port(ExitPortRange::Single(v)) => *v == port,
            ExitPolicyPort::Port(ExitPortRange::Interval(from, to)) => *from <= port && port <= *to,
        }
    }
}
impl DescriptorExitPolicyRule {
    pub fn to_string(&self) -> String {
        self.ep_type.to_string()
            + " "
            + self.address.to_string().as_str()
            + ":"
            + self.port.to_string().as_str()
    }
}
#[derive(Debug, Clone)]
pub struct DescriptorExitPolicy {
    pub rules: Vec<DescriptorExitPolicyRule>,
}
impl DescriptorExitPolicy {
    pub(super) fn new() -> Self {
        DescriptorExitPolicy { rules: Vec::new() }
    }

    pub(super) fn add_rule(&mut self, epr: DescriptorExitPolicyRule) {
        self.rules.push(epr);
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct DescriptorExitPolicyIPv6 {
    policy: ExitPolicyType,
    port_list: Vec<Value<u16>>,
}

impl Default for DescriptorExitPolicyIPv6 {
    fn default() -> Self {
        // A missing "ipv6-policy" line is equivalent to "ipv6-policy reject 1-65535".
        DescriptorExitPolicyIPv6 {
            policy: ExitPolicyType::Reject,
            port_list: vec![Value::Range(1, 65535)],
        }
    }
}

fn parse_exit_policy_address(addr_str: &str) -> Result<ExitPolicyAddress, DocumentParseError> {
    if addr_str == "*" {
        return Ok(ExitPolicyAddress::Wildcard);
    } else {
        let network = {
            if addr_str.contains('/') {
                IpNet::from_str(addr_str)
                    .map_err(|_| DocumentParseError::IpParseError(addr_str.to_string()))?
            } else {
                let addr = addr_str
                    .parse::<IpAddr>()
                    .map_err(|_| DocumentParseError::IpParseError(addr_str.to_string()))?;
                IpNet::new(addr, 32).unwrap() // cannot panic because the provided prefix length 32 is valid
            }
        };
        return Ok(ExitPolicyAddress::Address(network));
    }
}

#[derive(PartialEq, Clone, Debug)]
pub enum Value<T> {
    Single(T),
    Range(T, T),
}

pub(super) fn parse_exit_policy_port(port_str: &str) -> Result<ExitPolicyPort, DocumentParseError> {
    match port_str {
        "*" => Ok(ExitPolicyPort::Wildcard),
        _ => Ok(ExitPolicyPort::Port(parse_range(port_str)?)),
    }
}

pub(super) fn parse_kw_accept<'a>(
    descriptor: &mut DescriptorBuilder,
    item: &Item<'a>,
) -> Result<(), DocumentParseError> {
    parse_exit_policy_rule(descriptor, item, ExitPolicyType::Accept)
}

pub(super) fn parse_kw_reject<'a>(
    descriptor: &mut DescriptorBuilder,
    item: &Item<'a>,
) -> Result<(), DocumentParseError> {
    parse_exit_policy_rule(descriptor, item, ExitPolicyType::Reject)
}

pub(super) fn parse_exit_policy_rule<'a>(
    descriptor: &mut DescriptorBuilder,
    item: &Item<'a>,
    ept: ExitPolicyType,
) -> Result<(), DocumentParseError> {
    let arg = item.get_argument()?;
    let splits: Vec<&str> = arg.split(':').collect();
    match splits[..] {
        [address, port, ..] => {
            descriptor.add_exit_policy_rule(DescriptorExitPolicyRule {
                ep_type: ept,
                address: parse_exit_policy_address(address)?,
                port: parse_exit_policy_port(port)?,
            });
            Ok(())
        }
        _ => Err(DocumentParseError::args_missing(item.keyword)),
    }
}

pub(super) fn parse_kw_ipv6_policy<'a>(
    builder: &mut DescriptorBuilder,
    item: &Item<'a>,
) -> Result<(), DocumentParseError> {
    let (policy_str, port_list_str) = item
        .get_argument()?
        .split_once(' ')
        .ok_or_else(|| DocumentParseError::args_missing(item.keyword))?;

    let policy = match policy_str {
        "accept" => ExitPolicyType::Accept,
        "reject" => ExitPolicyType::Reject,
        _ => return Err(DocumentParseError::PolicyParseError(policy_str.to_string())),
    };
    let port_list: Vec<Value<u16>> = parse_values(port_list_str)?;
    let ipv6_policy = DescriptorExitPolicyIPv6 {
        policy: policy,
        port_list: port_list,
    };
    builder.exit_policies_ipv6(ipv6_policy);
    Ok(())
}

fn parse_custom_error<T: std::str::FromStr>(input: &str) -> Result<T, DocumentParseError> {
    let type_str = std::any::type_name::<T>();
    match input.parse::<T>() {
        Ok(s) => Ok(s),
        /* We try to cast e to dyn std::error::Error */
        Err(_) => Err(DocumentParseError::ValueParseError(String::from(type_str))),
    }
}

// Value = Int
// Value = Int "-" Int
fn parse_value<T: std::str::FromStr>(input: &str) -> Result<Value<T>, DocumentParseError> {
    let split = &mut input.split('-').collect::<Vec<&str>>();
    match split[..] {
        [single] => Ok(Value::Single(parse_custom_error(single)?)),
        [first, second, ..] => Ok(Value::Range(
            parse_custom_error(first)?,
            parse_custom_error(second)?,
        )),
        _ => Err(DocumentParseError::args_missing(input)),
    }
}

// Values =
// Values = Value
// Values = Value "," Values
fn parse_values<T: std::str::FromStr>(input: &str) -> Result<Vec<Value<T>>, DocumentParseError> {
    let mut values: Vec<Value<T>> = Vec::new();
    for current_value in &mut input.split(',') {
        values.push(parse_value(current_value)?);
    }
    Ok(values)
}

fn parse_range<T: std::str::FromStr>(input: &str) -> Result<ExitPortRange<T>, DocumentParseError> {
    let input_split: Vec<&str> = input.split('-').collect();

    match input_split[..] {
        [min, max, ..] => Ok(ExitPortRange::Interval(
            min.parse::<T>()
                .map_err(|_| DocumentParseError::RangeParseError(min.to_string()))?,
            max.parse::<T>()
                .map_err(|_| DocumentParseError::RangeParseError(max.to_string()))?,
        )),
        [value, ..] => {
            Ok(ExitPortRange::Single(value.parse::<T>().map_err(|_| {
                DocumentParseError::RangeParseError(value.to_string())
            })?))
        }
        _ => Err(DocumentParseError::args_missing(input)),
    }
}

// fn set_default_values<'a>(descriptor: &mut Descriptor) {
//     if let None = descriptor.exit_policies_ipv6 {
//         // A missing "ipv6-policy" line is equivalent to "ipv6-policy reject 1-65535".
//         let default_policy = DescriptorExitPolicyIPv6 {
//             policy: ExitPolicyType::Reject,
//             port_list: vec![Value::Range(1, 65535)],
//         };
//         descriptor.exit_policies_ipv6 = Some(default_policy);
//     }
//     /* Currently needed for  family_relations code */
//     if let None = descriptor.family_members {
//         descriptor.family_members = Some(vec![]);
//     }
// }
