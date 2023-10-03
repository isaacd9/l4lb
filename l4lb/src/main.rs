mod config;

use anyhow::{Context, Ok};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, maps::HashMap, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use config::Config;
use l4lb_common::VipKey;
use log::{debug, info, warn};
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

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
