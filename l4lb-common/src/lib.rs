#![no_std]
#![no_main]

#[cfg(feature = "user")]
use aya::Pod;

use network_types::ip::IpProto;

// This is a 5tuple struct for IPv4 which is used to identify a flow
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FiveTuple {
    pub source_addr: u32,
    pub source_port: u16,
    pub dst_addr: u32,
    pub dst_port: u16,
    pub proto: IpProto,
}

#[cfg(feature = "user")]
unsafe impl Pod for FiveTuple {}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct VipKey {
    pub addr: u32,
    pub port: u16,
    pub proto: IpProto,
}

#[cfg(feature = "user")]
unsafe impl Pod for VipKey {}
