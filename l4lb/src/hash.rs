use crate::config::RealServer;
use mur3;
use std::{hash::Hasher, vec};

pub trait ConsistentHasher {
    fn generate_hash_ring(&self, vip_no: u16, reals: &[RealServer]) -> Vec<RealServer>;
}

pub struct SimpleConsistentHasher {
    ring_size: u32,
}

impl SimpleConsistentHasher {
    pub fn new(ring_size: u32) -> Self {
        SimpleConsistentHasher { ring_size }
    }
}

// Simple consistent hashing algorithm that splits the hash ring into equal
// sized chunks and assigns each real server to a chunk. This is not a very good
// algorithm.
impl ConsistentHasher for SimpleConsistentHasher {
    fn generate_hash_ring(&self, _vip_no: u16, reals: &[RealServer]) -> Vec<RealServer> {
        let chunk_size = self.ring_size / reals.len() as u32;
        let mut ring = Vec::with_capacity(self.ring_size as usize);

        for i in 0..self.ring_size {
            let mut chunk = i / chunk_size;
            // If we're at the end of the ring, we need to use the last chunk
            if chunk >= reals.len() as u32 {
                chunk = reals.len() as u32 - 1;
            }
            ring.push(reals[chunk as usize]);
        }

        ring
    }
}

pub struct MaglevConsistentHasher {
    ring_size: u32,
}

#[derive(Debug)]
struct Permutation(u32, u32);

impl MaglevConsistentHasher {
    pub fn new(ring_size: u32) -> Self {
        MaglevConsistentHasher { ring_size }
    }
}

const OFFSET_SEED: u32 = 0xdeadbeef;
const SKIP_SEED: u32 = 0xbaadf00d;

fn hash(num: u32, server: &RealServer, seed: u32) -> u32 {
    let mut hasher = mur3::Hasher32::with_seed(seed);
    hasher.write_u32(num);
    hasher.write_u32(server.addr.into());
    hasher.write_u16(server.port);
    hasher.finish() as u32
}

fn generate_permutation(num: u32, ring_size: u32, server: &RealServer) -> Permutation {
    let offset_hash = hash(num, server, OFFSET_SEED);
    let offset = offset_hash % ring_size;

    let skip_hash = hash(num, server, SKIP_SEED);
    let skip = (skip_hash % (ring_size - 1)) + 1;

    Permutation(offset, skip)
}

impl ConsistentHasher for MaglevConsistentHasher {
    fn generate_hash_ring(&self, vip_no: u16, reals: &[RealServer]) -> Vec<RealServer> {
        let mut ring: Vec<Option<RealServer>> = vec![None; self.ring_size as usize];
        let mut next: Vec<usize> = vec![0; reals.len()];

        let permutations: Vec<Permutation> = reals
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let num: u32 = (vip_no as u32) << 16_u32 | i as u32;
                generate_permutation(num, self.ring_size, r)
            })
            .collect();

        let mut filled = 0;

        // TODO: support weighted servers
        loop {
            for (i, permuation) in permutations.iter().enumerate() {
                /*
                println!(
                    "trying to place server {} in ring. permutation: {:?}. cur ring: {:?}",
                    i, permuation, ring
                );
                 */
                let (offset, skip) = (permuation.0 as usize, permuation.1 as usize);
                // Get the next server in the permutation
                let mut cur = (offset + skip * next[i]) % (self.ring_size as usize);

                // Find the next empty slot in the ring based on the offset and
                // skip
                while ring[cur] != None {
                    next[i] += 1;
                    cur = (offset + skip * next[i]) % self.ring_size as usize;
                }

                // Place the server in the ring and increment the next index
                ring[cur] = Some(reals[i]);
                next[i] += 1;
                filled += 1;

                // If the ring is full, return it
                if filled >= self.ring_size {
                    return ring.into_iter().map(|x| x.unwrap()).collect();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple_consistent_hasher() {
        let reals = vec![
            RealServer {
                addr: "192.168.1.1".parse().unwrap(),
                port: 80,
            },
            RealServer {
                addr: "192.168.1.2".parse().unwrap(),
                port: 81,
            },
            RealServer {
                addr: "192.168.1.3".parse().unwrap(),
                port: 82,
            },
        ];

        let ch = SimpleConsistentHasher::new(6);
        let ring = ch.generate_hash_ring(0, &reals);

        // TODO: DRY this up
        for (i, real) in ring.iter().enumerate() {
            if i < 2 {
                assert_eq!(real, &reals[0]);
            } else if i < 4 {
                assert_eq!(real, &reals[1]);
            } else {
                assert_eq!(real, &reals[2]);
            }
        }

        let ch = SimpleConsistentHasher::new(7);
        let ring = ch.generate_hash_ring(0, &reals);

        for (i, real) in ring.iter().enumerate() {
            if i < 2 {
                assert_eq!(real, &reals[0]);
            } else if i < 4 {
                assert_eq!(real, &reals[1]);
            } else {
                assert_eq!(real, &reals[2]);
            }
        }
    }

    macro_rules! ip {
        ($ip:literal) => {
            $ip.parse().unwrap()
        };
    }

    #[test]
    fn test_maglev_consistent_hasher() {
        let reals = vec![
            RealServer {
                addr: ip!("192.168.1.1"),
                port: 80,
            },
            RealServer {
                addr: ip!("192.168.1.2"),
                port: 81,
            },
            RealServer {
                addr: ip!("192.168.1.3"),
                port: 82,
            },
        ];

        let ch = MaglevConsistentHasher::new(11);
        let ring = ch.generate_hash_ring(0, &reals);

        let desired = vec![
            RealServer {
                addr: ip!("192.168.1.2"),
                port: 81,
            },
            RealServer {
                addr: ip!("192.168.1.3"),
                port: 82,
            },
            RealServer {
                addr: ip!("192.168.1.3"),
                port: 82,
            },
            RealServer {
                addr: ip!("192.168.1.1"),
                port: 80,
            },
            RealServer {
                addr: ip!("192.168.1.1"),
                port: 80,
            },
            RealServer {
                addr: ip!("192.168.1.2"),
                port: 81,
            },
            RealServer {
                addr: ip!("192.168.1.1"),
                port: 80,
            },
            RealServer {
                addr: ip!("192.168.1.2"),
                port: 81,
            },
            RealServer {
                addr: ip!("192.168.1.3"),
                port: 82,
            },
            RealServer {
                addr: ip!("192.168.1.2"),
                port: 81,
            },
            RealServer {
                addr: ip!("192.168.1.1"),
                port: 80,
            },
        ];
    }
}
