use serde::Deserialize;

use network_types::ip::IpProto;
use std::mem::transmute;
use std::net::Ipv4Addr;

#[derive(Debug, PartialEq, Deserialize)]
struct RealServer {
    addr: Ipv4Addr,
    port: u16,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct Config {
    vip: Ipv4Addr,
    port: u16,
    #[serde(deserialize_with = "deserialize_ip_proto")]
    proto: IpProto,
    real_servers: Vec<RealServer>,
}

fn deserialize_ip_proto<'de, D>(deserializer: D) -> Result<IpProto, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error;

    let s = u8::deserialize(deserializer).map_err(Error::custom)?;
    let proto: IpProto = unsafe { transmute(s) };
    Ok(proto)
}
