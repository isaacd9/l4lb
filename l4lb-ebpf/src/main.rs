#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{array::Array, hash_map::HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::{debug, info};
use core::mem;
use l4lb_common::{FiveTuple, RealServer, VipKey, CH_RINGS_SIZE, MAX_REALS, MAX_VIPS, RING_SIZE};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    tcp::TcpHdr,
    udp::UdpHdr,
};

#[map]
// Map of VIP key to vip number for the VIP consistent hah table
static VIP_INFO: HashMap<VipKey, u32> = HashMap::with_max_entries(MAX_VIPS, 0);
// REVERSE_VIP_INFO is a map of RealServer to VipKey. This is used for packets _from_ a real server to a client.
#[map]
static REVERSE_VIP_INFO: HashMap<RealServer, VipKey> = HashMap::with_max_entries(MAX_REALS, 0);
// CH_RINGS is an array of u32s that represent the index of the real server in the REALS array
#[map]
static CH_RINGS: Array<u32> = Array::with_max_entries(CH_RINGS_SIZE, 0);
// REALS is an array of all RealServer structs
#[map]
static REALS: Array<RealServer> = Array::with_max_entries(MAX_REALS, 0);

#[xdp]
pub fn l4lb(ctx: XdpContext) -> u32 {
    match try_l4lb(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)] //
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *mut T)
}

enum TransportProtocolHeader {
    Tcp(*mut TcpHdr),
    Udp(*mut UdpHdr),
}

#[inline(always)]
fn format_flags(hdr: &TransportProtocolHeader) -> &'static str {
    use TransportProtocolHeader::*;

    match *hdr {
        Tcp(h) => {
            if unsafe { (*h).syn() } == 0x1 {
                if unsafe { (*h).ack() } == 0x1 {
                    "SYN,ACK"
                } else {
                    "SYN"
                }
            } else if unsafe { (*h).fin() } == 0x1 {
                if unsafe { (*h).ack() } == 0x1 {
                    "FIN,ACK"
                } else {
                    "FIN"
                }
            } else if unsafe { (*h).ack() } == 0x1 {
                "ACK"
            } else {
                ""
            }
        }
        _ => "",
    }
}

fn get_vip_number(vip: VipKey) -> Option<u32> {
    unsafe { VIP_INFO.get(&vip).copied() }
}

fn get_reverse_vip(real: RealServer) -> Option<VipKey> {
    unsafe { REVERSE_VIP_INFO.get(&real).copied() }
}

// terrible hash function for now
#[inline(always)]
fn hash(flow: FiveTuple) -> u32 {
    let mut hash = flow.source_addr;
    hash ^= flow.source_port as u32;
    hash ^= flow.dst_addr as u32;
    hash ^= flow.dst_port as u32;
    hash ^= flow.proto as u32;
    hash
}

fn get_dest(vip_number: u32, flow: FiveTuple) -> Option<RealServer> {
    let hash = hash(flow);
    let index = hash % RING_SIZE;

    let real_index = (vip_number * RING_SIZE) + CH_RINGS.get(index).copied()?;

    REALS.get(real_index).copied()
}

#[inline(always)]
fn ipv4_checksum(hdr: *const Ipv4Hdr) -> u16 {
    let ptr = hdr as *const u16;
    // This length is static, and won't support IPv4 headers with options.
    let length = Ipv4Hdr::LEN;
    let mut sum: u32 = 0;

    // Divide the header into 16-bit chunks and sum them. Need to divide by 2
    // because size of is byte-denominated.
    for i in 0..(length / 2) {
        sum += unsafe { *(ptr.add(i)) } as u32;
    }

    while sum >> 16_u32 != 0 {
        sum = (sum & 0xffff) + (sum >> 16_u32);
    }

    !(sum as u16)
}

// #[inline(always)]
fn incremental_tcp_checksum(old_checksum: u16, old_port: u16, new_port: u16) -> u16 {
    let mut sum = old_checksum as u32;
    sum -= old_port as u32;
    sum += new_port as u32;

    while sum >> 16_u32 != 0 {
        sum = (sum & 0xffff) + (sum >> 16_u32);
    }

    !(sum as u16)
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
struct Mangle {
    src_addr: u32,
    src_port: u16,
    dst_addr: u32,
    dst_port: u16,
}

fn mangle_packet(ipv4hdr: *mut Ipv4Hdr, protocol_header: TransportProtocolHeader, mangle: Mangle) {
    unsafe { (*ipv4hdr).src_addr = u32::to_be(mangle.src_addr) };
    unsafe { (*ipv4hdr).dst_addr = u32::to_be(mangle.dst_addr) };

    // Zero out the checksum before computing it
    unsafe { (*ipv4hdr).check = 0 };
    // It's possible that we could eliminate this by doing some math on the
    // checksum to avoid recomputing the whole thing. For now tho, just
    // recompute the entire checksum.
    unsafe { (*ipv4hdr).check = ipv4_checksum(ipv4hdr) }

    // TODO: update the ports in the transport header
    match protocol_header {
        TransportProtocolHeader::Tcp(tcphdr) => {
            unsafe {
                (*tcphdr).check = u16::to_be(incremental_tcp_checksum(
                    u16::from_be((*tcphdr).check),
                    u16::from_be((*tcphdr).source),
                    mangle.src_port,
                ))
            };
            unsafe {
                (*tcphdr).check = u16::to_be(incremental_tcp_checksum(
                    u16::from_be((*tcphdr).check),
                    u16::from_be((*tcphdr).dest),
                    mangle.dst_port,
                ))
            };
            unsafe { (*tcphdr).source = u16::to_be(mangle.src_port) };
            unsafe { (*tcphdr).dest = u16::to_be(mangle.dst_port) };
        }
        TransportProtocolHeader::Udp(udphdr) => {
            unsafe { (*udphdr).source = u16::to_be(mangle.src_port) };
            unsafe { (*udphdr).dest = u16::to_be(mangle.dst_port) };
        }
    }
}

fn try_l4lb(ctx: XdpContext) -> Result<u32, ()> {
    use TransportProtocolHeader::*;

    let start = ctx.data();
    let end = ctx.data_end();
    let length = (end - start) as i32;

    debug!(&ctx, "received a packet: len={}", length);

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    // Only handle IPv4 for now
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Parse the IPv4 header
    let ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let proto = unsafe { (*ipv4hdr).proto };

    let (source_port, dst_port, header) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *mut TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            let source_port = u16::from_be(unsafe { (*tcphdr).source });
            let dst_port = u16::from_be(unsafe { (*tcphdr).dest });

            (source_port, dst_port, Tcp(tcphdr))
        }
        IpProto::Udp => {
            let udphdr: *mut UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            let source_port = u16::from_be(unsafe { (*udphdr).source });
            let dst_port = u16::from_be(unsafe { (*udphdr).dest });

            (source_port, dst_port, Udp(udphdr))
        }
        _ => return Err(()),
    };

    // This is a 5tuple
    let flow = FiveTuple {
        source_addr,
        source_port,
        dst_addr,
        dst_port,
        proto,
    };

    let flow_id = hash(flow);

    info!(
        &ctx,
        "[{}] SRC IP: {:i}, SRC PORT: {}, DST IP: {:i}, DST PORT: {}, PROTO: {}, FLAGS: [{}]",
        flow_id,
        source_addr,
        source_port,
        dst_addr,
        dst_port,
        proto as u8,
        format_flags(&header),
    );

    match get_reverse_vip(RealServer {
        addr: source_addr,
        port: source_port,
        proto,
    }) {
        Some(vip) => {
            // Update the packet to be from the VIP
            debug!(
                &ctx,
                "[{}] mangling packet from behind VIP: {:i}:{} dest: {:i}:{}",
                flow_id,
                vip.addr,
                vip.port,
                dst_addr,
                dst_port,
            );

            mangle_packet(
                ipv4hdr,
                header,
                Mangle {
                    src_addr: vip.addr,
                    src_port: vip.port,
                    dst_addr: dst_addr,
                    dst_port: dst_port,
                },
            );

            return Ok(xdp_action::XDP_TX);
        }
        None => {
            // This is a packet from a client
        }
    };

    let vip_number = match get_vip_number(VipKey {
        addr: dst_addr,
        port: dst_port,
        proto,
    }) {
        Some(vn) => vn,
        None => {
            // We don't have a VIP for this packet so pass it through. It's not
            // for us and shouldn't be mutated.
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let dest = match get_dest(vip_number, flow) {
        Some(d) => d,
        None => {
            // We don't have a real server for this VIP so drop the packet
            return Ok(xdp_action::XDP_DROP);
        }
    };

    debug!(
        &ctx,
        "[{}] mangling packet to VIP {}: src: {:i}:{} dest: {:i}:{}",
        flow_id,
        vip_number,
        source_addr,
        source_port,
        dest.addr,
        dest.port,
    );

    mangle_packet(
        ipv4hdr,
        header,
        Mangle {
            src_addr: source_addr,
            src_port: source_port,
            dst_addr: dest.addr,
            dst_port: dest.port,
        },
    );

    Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
