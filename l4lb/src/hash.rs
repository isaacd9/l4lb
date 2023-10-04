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
        let chunk_size = self.ring_size / reals.len() as u32;
        let mut ring = Vec::with_capacity(self.ring_size as usize);

        for i in 1..self.ring_size + 1 {
            let mut chunk = i / chunk_size;
            // If we're at the end of the ring, we need to wrap around
            if chunk >= reals.len() as u32 {
                chunk = reals.len() as u32 - 1;
            }
            ring.push(reals[chunk as usize]);
        }

        ring
    }
}
