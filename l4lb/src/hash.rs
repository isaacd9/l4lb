use crate::config::RealServer;

pub trait ConsistentHasher {
    fn generate_hash_ring(&self, reals: &[RealServer]) -> Vec<RealServer>;
}

pub struct SimpleConsistentHasher {
    ring_size: u32,
}

impl SimpleConsistentHasher {
    pub fn new(ring_size: u32) -> Self {
        SimpleConsistentHasher { ring_size }
    }
}

impl ConsistentHasher for SimpleConsistentHasher {
    fn generate_hash_ring(&self, reals: &[RealServer]) -> Vec<RealServer> {
        let mut ring = Vec::with_capacity(self.ring_size as usize);

        for i in 0..self.ring_size {
            let j = i % reals.len() as u32;
            ring.push(reals[j as usize]);
        }

        ring
    }
}
