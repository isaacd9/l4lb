#![no_std]
#![no_main]

#[cfg(feature = "user")]
use aya::Pod;

// This is the maximum number of VIPs that can be configured
pub const MAX_VIPS: u32 = 512;
// This is the maximum number of entries in an individual consistent hash ring
// This needs to be a prime number for the Maglev algorithm to work
pub const RING_SIZE: u32 = 65537;
// This is the maximum number of real IP addresses that can be configured
pub const MAX_REALS: u32 = 4096;
// This is the total size of the consistent hash ring array
pub const CH_RINGS_SIZE: u32 = RING_SIZE * MAX_VIPS;

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

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RealServer {
    pub addr: u32,
    pub port: u16,
    pub proto: IpProto,
}

#[cfg(feature = "user")]
unsafe impl Pod for RealServer {}
