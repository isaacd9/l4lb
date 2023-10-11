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
    ip::{self, IpProto, Ipv4Hdr},
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
    let length = Ipv4Hdr::LEN;
    let mut sum: u32 = 0;

    // Divide the header into 16-bit chunks and sum them. Need to divide by 2
    // because size of is byte-denominated.
    for i in 0..(length / 2) {
        sum += unsafe { *(ptr.add(i)) } as u32;
    }

    // If the length is odd, we need to add the last byte
    if length % 2 != 0 {
        // TODO: fix this
        // sum += unsafe { (*ptr as *const u8).add(length as usize) } as u32;
    }

    while sum >> 16_u32 != 0 {
        sum = (sum & 0xffff) + (sum >> 16_u32);
    }

    !(sum as u16)
}

fn tcp_checksum(
    ctx: &XdpContext,
    ipv4hdr: *const Ipv4Hdr,
    tcphdr: *const TcpHdr,
) -> Result<u16, ()> {
    let mut sum: u32 = 0;
    // TCP pseudo header
    sum += unsafe { (*ipv4hdr).src_addr } as u32;
    sum += unsafe { (*ipv4hdr).dst_addr } as u32;
    let tot_len = u32::from_be(unsafe { (*ipv4hdr).tot_len } as u32);
    let ihl = u8::from_be(unsafe { (*ipv4hdr).ihl() }) as u32;
    let length = tot_len - (ihl * 4);
    sum += (unsafe { (*ipv4hdr).proto } as u32) << 16_u32 | length;

    /*
     */

    // sum of header and data
    let ptr = tcphdr as *const u16;
    let mut i = 0;
    // If the length is larger than 16 bits, we can't compute the checksum
    // let hdr_length = TcpHdr::LEN;
    // for i in 0..(hdr_length as usize / 2) {
    // sum += unsafe { *(ptr.add(i as usize)) } as u32;
    // }
    while i < (length / 2) {
        let c = unsafe { ptr.add(i as usize + 1) };
        if c > 0xffff as *const u16 {
            break;
        }
        sum += unsafe { *(ptr.add(i as usize)) } as u32;
        i += 1;
    }

    // TODO: compute the checksum of the data
    /*
    info!(
        ctx,
        "tcp checksum so far: {:x}. length: {}, hdr length: {}",
        sum,
        length,
        tot_len,
        ihl * 4,
        hdr_length,
        // unsafe { *ptr as u64 },
        // ctx.data_end() as u64,
    );
    */

    // If the length is odd, we need to add the last byte
    // if length % 2 != 0 {
    // sum += unsafe { (*ptr as *const u8).add(length as usize) } as u32;
    // }

    while sum >> 16_u32 != 0 {
        sum = (sum & 0xffff) + (sum >> 16_u32);
    }

    Ok(!(sum as u16))
}

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

fn mangle_packet(
    ctx: &XdpContext,
    ipv4hdr: *mut Ipv4Hdr,
    protocol_header: TransportProtocolHeader,
    mangle: Mangle,
) {
    unsafe { (*ipv4hdr).src_addr = u32::to_be(mangle.src_addr) };
    unsafe { (*ipv4hdr).dst_addr = u32::to_be(mangle.dst_addr) };

    // It's possible that we could eliminate this by doing some math on the
    // checksum to avoid recomputing the whole thing. For now tho, just
    // recompute the entire checksum.
    let old_checksum = unsafe { (*ipv4hdr).check };
    // Zero out the checksum before computing it
    unsafe { (*ipv4hdr).check = 0 };
    unsafe { (*ipv4hdr).check = ipv4_checksum(ipv4hdr) }
    debug!(
        ctx,
        "recomputing checksum, old sum: {:x}, new checksum: {:x}",
        old_checksum,
        { unsafe { (*ipv4hdr).check } }
    );

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
            // unsafe { (*tcphdr).check = 0 };
            /*
            let check = match tcp_checksum(ctx, ipv4hdr, tcphdr) {
                Ok(c) => c,
                Err(_) => {
                    info!(ctx, "failed to compute tcp checksum");
                    return;
                }
            };

            unsafe { (*tcphdr).check = check };
            */
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

    info!(&ctx, "received a packet: len={}", length);

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

    match get_reverse_vip(RealServer {
        addr: source_addr,
        port: source_port,
        proto,
    }) {
        Some(vip) => {
            debug!(&ctx, "reverse vip found: {:i}:{}", vip.addr, vip.port);
            // Update the packet to be from the VIP
            mangle_packet(
                &ctx,
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
            debug!(&ctx, "unknown real server");
        }
    };

    let vip_number = match get_vip_number(VipKey {
        addr: dst_addr,
        port: dst_port,
        proto,
    }) {
        Some(vn) => vn,
        None => {
            debug!(&ctx, "unknown vip");
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

    debug!(
        &ctx,
        "routing packet VIP: {}, {:i}:{}", vip_number, dest.addr, dest.port
    );

    mangle_packet(
        &ctx,
        ipv4hdr,
        header,
        Mangle {
            src_addr: source_addr,
            src_port: source_port,
            dst_addr: dest.addr,
            dst_port: dest.port,
        },
    );

    let new_ipv4hdr: *mut Ipv4Hdr = ptr_at(&ctx, EthHdr::LEN)?;
    debug!(
        &ctx,
        "packet mangled: {:i}",
        u32::from_be(unsafe { (*new_ipv4hdr).dst_addr })
    );

    Ok(xdp_action::XDP_TX)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
