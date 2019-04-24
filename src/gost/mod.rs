use padding;
use padding_index;

const BLOCK_SIZE: usize = 8;    // bytes (2 x u32, 54 bit)
const K8: [u8; 16] = [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7];
const K7: [u8; 16] = [15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10];
const K6: [u8; 16] = [10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8];
const K5: [u8; 16] = [ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15];
const K4: [u8; 16] = [ 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9];
const K3: [u8; 16] = [12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11];
const K2: [u8; 16] = [ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1];
const K1: [u8; 16] = [13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7];


pub struct Gost {
    k: [u32; 8],
    k87: [u8; 256],
    k65: [u8; 256],
    k43: [u8; 256],
    k21: [u8; 256],
}

pub fn new(key: &[u8]) -> Result<Gost, &str> {
	let mut k = [0u32; 8];
   let mut k87 = [0u8; 256];
   let mut k65 = [0u8; 256];
   let mut k43 = [0u8; 256];
   let mut k21 = [0u8; 256];
    
   let mut i = 0usize;
   while i < 256 {
   	let idx1 = i >> 4;
      let idx2 = i & 15;
      k87[i] = (K8[idx1] << 4) | K7[idx2];
		k65[i] = (K6[idx1] << 4) | K5[idx2];
		k43[i] = (K4[idx1] << 4) | K3[idx2];
		k21[i] = (K2[idx1] << 4) | K1[idx2];
      i += 1;
	}

	i = 0usize;
	while i < 8 {
		let mut idx = (i * 4) + 3;
		let mut v = 0u32;
		v = (v << 8) + key[idx] as u32; idx -= 1;
		v = (v << 8) + key[idx] as u32; idx -= 1;
		v = (v << 8) + key[idx] as u32; idx -= 1;
		v = (v << 8) + key[idx] as u32;
		k[i] = v;
		i += 1;
	}

    Ok(Gost{k, k87, k65, k43, k21})
}

impl Gost {
	fn f(&self, x: u32) -> u32 {
		let i0 = (x >> 24) & 0xff;
		let i1 = (x >> 16) & 0xff;
		let i2 = (x >>  8) & 0xff;
		let i3 = x & 0xff;
		
		let w0 = (self.k87[i0 as usize] as u32) << 24;
		let w1 = (self.k65[i1 as usize] as u32) << 16;
		let w2 = (self.k43[i2 as usize] as u32) << 8;
		let w3 = self.k21[i3 as usize] as u32;
		let x = w0 | w1 | w2 | w3;
		(x << 11) | (x >> (32 - 11))
	}
	
	pub fn encrypt(&self, mut xl: u32, mut xr: u32) -> (u32, u32) {
		xr ^= self.f(xl + self.k[0]);
		xl ^= self.f(xr + self.k[1]);
		xr ^= self.f(xl + self.k[2]);
		xl ^= self.f(xr + self.k[3]);
		xr ^= self.f(xl + self.k[4]);
		xl ^= self.f(xr + self.k[5]);
		xr ^= self.f(xl + self.k[6]);
		xl ^= self.f(xr + self.k[7]);

		xr ^= self.f(xl + self.k[0]);
		xl ^= self.f(xr + self.k[1]);
		xr ^= self.f(xl + self.k[2]);
		xl ^= self.f(xr + self.k[3]);
		xr ^= self.f(xl + self.k[4]);
		xl ^= self.f(xr + self.k[5]);
		xr ^= self.f(xl + self.k[6]);
		xl ^= self.f(xr + self.k[7]);

		xr ^= self.f(xl + self.k[0]);
		xl ^= self.f(xr + self.k[1]);
		xr ^= self.f(xl + self.k[2]);
		xl ^= self.f(xr + self.k[3]);
		xr ^= self.f(xl + self.k[4]);
		xl ^= self.f(xr + self.k[5]);
		xr ^= self.f(xl + self.k[6]);
		xl ^= self.f(xr + self.k[7]);

		xr ^= self.f(xl + self.k[7]);
		xl ^= self.f(xr + self.k[6]);
		xr ^= self.f(xl + self.k[5]);
		xl ^= self.f(xr + self.k[4]);
		xr ^= self.f(xl + self.k[3]);
		xl ^= self.f(xr + self.k[2]);
		xr ^= self.f(xl + self.k[1]);
		xl ^= self.f(xr + self.k[0]);

		(xr, xl)
	}
	
	pub fn decrypt(&self, mut xl: u32, mut xr: u32) -> (u32, u32) {
		xr ^= self.f(xl + self.k[0]);
		xl ^= self.f(xr + self.k[1]);
		xr ^= self.f(xl + self.k[2]);
		xl ^= self.f(xr + self.k[3]);
		xr ^= self.f(xl + self.k[4]);
		xl ^= self.f(xr + self.k[5]);
		xr ^= self.f(xl + self.k[6]);
		xl ^= self.f(xr + self.k[7]);

		xr ^= self.f(xl + self.k[7]);
		xl ^= self.f(xr + self.k[6]);
		xr ^= self.f(xl + self.k[5]);
		xl ^= self.f(xr + self.k[4]);
		xr ^= self.f(xl + self.k[3]);
		xl ^= self.f(xr + self.k[2]);
		xr ^= self.f(xl + self.k[1]);
		xl ^= self.f(xr + self.k[0]);

		xr ^= self.f(xl + self.k[7]);
		xl ^= self.f(xr + self.k[6]);
		xr ^= self.f(xl + self.k[5]);
		xl ^= self.f(xr + self.k[4]);
		xr ^= self.f(xl + self.k[3]);
		xl ^= self.f(xr + self.k[2]);
		xr ^= self.f(xl + self.k[1]);
		xl ^= self.f(xr + self.k[0]);

		xr ^= self.f(xl + self.k[7]);
		xl ^= self.f(xr + self.k[6]);
		xr ^= self.f(xl + self.k[5]);
		xl ^= self.f(xr + self.k[4]);
		xr ^= self.f(xl + self.k[3]);
		xl ^= self.f(xr + self.k[2]);
		xr ^= self.f(xl + self.k[1]);
		xl ^= self.f(xr + self.k[0]);

		(xr, xl)
	}
}
