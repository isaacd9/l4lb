#![no_std]
#![no_main]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{array::Array, hash_map::HashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
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
#[map]
static CH_RINGS: Array<u32> = Array::with_max_entries(CH_RINGS_SIZE, 0);
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
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

enum Header {
    Tcp(*const TcpHdr),
    Udp(*const UdpHdr),
}

fn format_flags(hdr: &Header) -> &'static str {
    use Header::*;

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

// terrible hash function for now
fn hash(flow: FiveTuple) -> u32 {
    let mut hash = flow.source_addr ^ flow.source_port as u32;
    hash ^= flow.dst_addr;
    hash ^= flow.dst_port as u32;
    hash ^= flow.proto as u32;
    hash
}

fn get_dest(vip_number: u32, flow: FiveTuple) -> Option<RealServer> {
    let mut hash = hash(flow);
    let mut index = hash % RING_SIZE;

    let real_index = (vip_number * RING_SIZE) + unsafe { CH_RINGS.get(index).copied() }?;
    unsafe { REALS.get(real_index).copied() }
}

fn try_l4lb(ctx: XdpContext) -> Result<u32, ()> {
    use Header::*;

    let start = ctx.data();
    let end = ctx.data_end();
    let length = (end - start) as i32;

    info!(&ctx, "received a packet: len={}", length);

    let ethhdr: *const EthHdr = ptr_at(&ctx, 0)?;
    // Only handle IPv4 for now
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    // Parse the IPv4 header
    let ipv4hdr: *const Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    let source_addr = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let dst_addr = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let proto = unsafe { (*ipv4hdr).proto };

    let (source_port, dst_port, header) = match unsafe { (*ipv4hdr).proto } {
        IpProto::Tcp => {
            let tcphdr: *const TcpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            let source_port = u16::from_be(unsafe { (*tcphdr).source });
            let dst_port = u16::from_be(unsafe { (*tcphdr).dest });

            (source_port, dst_port, Tcp(tcphdr))
        }
        IpProto::Udp => {
            let udphdr: *const UdpHdr = ptr_at(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

            let source_port = u16::from_be(unsafe { (*udphdr).source });
            let dst_port = u16::from_be(unsafe { (*udphdr).dest });

            (source_port, dst_port, Udp(udphdr))
        }
        _ => return Err(()),
    };

    info!(
        &ctx,
        "SRC IP: {:i}, SRC PORT: {}, DST IP: {:i}, DST PORT: {}, PROTO: {}, FLAGS: [{}]",
        source_addr,
        source_port,
        dst_addr,
        dst_port,
        proto as u8,
        format_flags(&header),
    );

    // This is a 5tuple
    let flow = FiveTuple {
        source_addr,
        source_port,
        dst_addr,
        dst_port,
        proto,
    };
    let vip = VipKey {
        addr: dst_addr,
        port: dst_port,
        proto,
    };

    let vip_number = match get_vip_number(vip) {
        Some(vn) => {
            info!(&ctx, "found VIP! VIP NUMBER: {}", vn);
            vn
        }
        None => {
            info!(&ctx, "unknown vip");
            return Ok(xdp_action::XDP_PASS);
        }
    };

    let dest = match get_dest(vip_number, flow) {
        Some(d) => d,
        None => {
            info!(&ctx, "unknown dest");
            return Ok(xdp_action::XDP_DROP);
        }
    };

    info!(
        &ctx,
        "found real server! REAL SERVER: {:i}:{}", dest.addr, dest.port
    );

    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
