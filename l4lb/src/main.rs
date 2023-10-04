mod config;
mod hash;

use anyhow::{Context, Ok};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use config::Config;
use hash::ConsistentHasher;
use l4lb_common::{RealServer, VipKey};
use log::{debug, info, warn};
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "eth0")]
    iface: String,
    #[clap(short, long)]
    config: String,
}

fn load_config(opt: &Opt) -> Result<Config, anyhow::Error> {
    let mut config_file = File::open(&opt.config)?;
    let mut config_contents = String::new();
    config_file.read_to_string(&mut config_contents)?;
    let config: Config = serde_yaml::from_str(&config_contents)?;
    Ok(config)
}

fn populate_vip_map(config: &Config, bpf: &mut Bpf) -> Result<(), anyhow::Error> {
    use aya::maps::HashMap;

    let mut vip_map: HashMap<_, VipKey, u32> = HashMap::try_from(bpf.map_mut("VIP_INFO").unwrap())?;

    for (i, vip) in config.vips.iter().enumerate() {
        let vip_key = VipKey {
            addr: vip.vip.into(),
            port: vip.port,
            proto: vip.proto,
        };
        vip_map.insert(&vip_key, i as u32, 0)?;
        debug!("Added VIP {:?} to map", vip_key);
    }
    Ok(())
}

struct ConsistentHashPopulator<H: ConsistentHasher> {
    ch_rings: Vec<u32>,
    reals: Vec<RealServer>,
    real_to_index: HashMap<config::RealServer, usize>,
    conistent_hasher: H,
}

impl<H: ConsistentHasher> ConsistentHashPopulator<H> {
    fn new(config: &Config, ch: H) -> Self {
        let mut populator = ConsistentHashPopulator {
            ch_rings: Vec::new(),
            reals: Vec::new(),
            real_to_index: HashMap::new(),
            conistent_hasher: ch,
        };

        populator.build_real_list(config);
        populator.build_ch_rings(config);
        populator
    }

    fn build_real_list(&mut self, config: &Config) {
        // Build real server list
        for vip in config.vips.iter() {
            for real in vip.real_servers.iter() {
                let real_server = RealServer {
                    addr: real.addr.into(),
                    port: real.port,
                };

                if self.real_to_index.contains_key(&real) {
                    continue;
                }

                self.reals.push(real_server);
                self.real_to_index.insert(*real, self.reals.len() - 1);
            }
        }
    }

    fn build_ch_rings(&mut self, config: &Config) {
        // Build consistent hash rings
        for vip in config.vips.iter() {
            let ring = self.conistent_hasher.generate_hash_ring(&vip.real_servers);
            for real in ring.iter() {
                let index = self.real_to_index[real];
                self.ch_rings.push(index as u32);
            }
        }
    }

    pub fn populate(&self, bpf: &mut Bpf) -> Result<(), anyhow::Error> {
        self.populate_ch_rings(bpf)?;
        self.populate_reals(bpf)?;
        Ok(())
    }

    fn populate_ch_rings(&self, bpf: &mut Bpf) -> Result<(), anyhow::Error> {
        use aya::maps::Array;
        let mut ch_rings_map: Array<_, u32> = Array::try_from(bpf.map_mut("CH_RINGS").unwrap())?;

        for (i, real) in self.ch_rings.iter().enumerate() {
            ch_rings_map.set(i as u32, real, 0)?;

            debug!("Added ring {} to map", real);
        }

        Ok(())
    }

    fn populate_reals(&self, bpf: &mut Bpf) -> Result<(), anyhow::Error> {
        use aya::maps::Array;
        let mut reals_map: Array<_, RealServer> = Array::try_from(bpf.map_mut("REALS").unwrap())?;

        for (i, real) in self.reals.iter().enumerate() {
            reals_map.set(i as u32, real, 0)?;

            debug!("Added real server {:?} to map", real);
        }

        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let opt = Opt::parse();

    let config = load_config(&opt).context("failed to load config")?;

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/l4lb"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/l4lb"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("l4lb").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    populate_vip_map(&config, &mut bpf)?;

    let ch_populator = ConsistentHashPopulator::new(
        &config,
        hash::SimpleConsistentHasher::new(l4lb_common::RING_SIZE),
    );
    ch_populator.populate(&mut bpf)?;

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
