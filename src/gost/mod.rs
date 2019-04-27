use padding;
use padding_index;
use bytes2block;
use block2bytes;

const BLOCK_SIZE: usize = 8;  // 8 bytes, 2 u32, 54 bit
const KEY_SIZE: usize = 32;	// 32 bytes, 8 u32, 256 bit
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

pub fn new(key: &[u8]) -> Result<Gost, String> {
	if key.len() != KEY_SIZE {
		return Err("invalid key size".to_string())
	}
	
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
		v = (v << 8) + (key[idx] as u32); idx -= 1;
		v = (v << 8) + (key[idx] as u32); idx -= 1;
		v = (v << 8) + (key[idx] as u32); idx -= 1;
		v = (v << 8) + (key[idx] as u32);
		k[i] = v;
		i += 1;
	}

    Ok(Gost{k, k87, k65, k43, k21})
}

impl Gost {
	
	/// encrypts vector of bytes in ECB mode
	pub fn encrypt_ecb(&self, input: &Vec<u8>) -> Result<Vec<u8>, String> {
		if input.len() == 0 { return Err("plain text size is 0".to_string()) }
				
		let plain = {
			let mut buffer = Vec::new();
			buffer.extend(input);
			let n = buffer.len() % BLOCK_SIZE;
			if n != 0 {
				buffer.extend(padding(BLOCK_SIZE -n));
			}
			buffer
		};
		let nbytes = plain.len();
		
		let mut cipher = Vec::with_capacity(nbytes);
		cipher.resize(nbytes, 0);
		
		let mut i = 0usize;
		while i < nbytes {
			let x = bytes2block(&plain[i..]);
			let x = self.encrypt(x);
			block2bytes(x, &mut cipher[i..]);
			i += BLOCK_SIZE;
		}
				
		Ok(cipher)
	}
	
	// decrypts vector of bytes in ECB mode
	pub fn decrypt_ecb(&self, cipher: &Vec<u8>) -> Result<Vec<u8>, String> {
		let nbytes = cipher.len();
		if nbytes == 0 { return Err("cipher text size is 0".to_string()) }
		
		let mut plain = Vec::with_capacity(nbytes);
		plain.resize(nbytes, 0);
		
		let mut i = 0usize;
		while i < nbytes {
			let x = bytes2block(&cipher[i..]);
			let x = self.decrypt(x);
			block2bytes(x, &mut plain[i..]);
			i += BLOCK_SIZE;
		}
		
		match padding_index(&plain) {
			Some(idx) => Ok(plain[..idx].to_vec()),
			_ => Ok(plain)
		}
	}

	/// Encrypts one block (two u32 words)
	pub fn encrypt(&self, x: (u32, u32)) -> (u32, u32) {
		self.encrypt_2u32(x.0, x.1)
	}
	
	#[inline]
	fn encrypt_2u32(&self, mut xl: u32, mut xr: u32) -> (u32, u32) {
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
	
	/// Decrypts one block (two u32 words)
	pub fn decrypt(&self, x: (u32, u32)) -> (u32, u32) {
		self.decrypt_2u32(x.0, x.1)
	}
	
	#[inline]
	pub fn decrypt_2u32(&self, mut xl: u32, mut xr: u32) -> (u32, u32) {
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
}

#[cfg(test)]
mod tests {
	use super::*;
		
	#[test]
	fn test_block_00() {
		let key = vec![0u8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0];

		let gt = new(&key).unwrap();
		let plain = (0u32, 0u32);
		let expected = (0x37ef7123u32, 0x361b7184u32);

		let encrypted = gt.encrypt(plain);
		assert_eq!(encrypted, expected);
		let decrypted = gt.decrypt(encrypted);
		assert_eq!(decrypted, plain);		
	}
	
	#[test]
	fn test_block_10() {
		let key = vec![0u8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0];

		let gt = new(&key).unwrap();
		let plain = (1u32, 0u32);
		let expected = (0x1159d751u32, 0xff9b91d2u32);

		let encrypted = gt.encrypt(plain);
		assert_eq!(encrypted, expected);
		let decrypted = gt.decrypt(encrypted);
		assert_eq!(decrypted, plain);				
	}

	#[test]
	fn test_block_01() {
		let key = vec![0u8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0];

		let gt = new(&key).unwrap();
		let plain = (0u32, 1u32);
		let expected = (0xc79c4ef4u32, 0x27ac9149u32);

		let encrypted = gt.encrypt(plain);
		assert_eq!(encrypted, expected);
		let decrypted = gt.decrypt(encrypted);
		assert_eq!(decrypted, plain);				
	}
	
	#[test]
	fn test_block_ff() {
		let key = vec![0u8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0];

		let gt = new(&key).unwrap();
		let plain = (0xffffffffu32, 0xffffffffu32);
		let expected = (0xf9709623u32, 0x56ad8d77u32);

		let encrypted = gt.encrypt(plain);
		assert_eq!(encrypted, expected);
		let decrypted = gt.decrypt(encrypted);
		assert_eq!(decrypted, plain);				
	}

	#[test]
	fn test_gost_ecb() {
		let key = vec![0u8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0];
		
		let gt = match new(&key) {
			Ok(x) => x,
			Err(err) => panic!(err)
		};
		
		let plain = "Yamato & Musashi".as_bytes().to_vec();
		let expected = vec![0x11, 0x97, 0xf2, 0x66, 0x20, 0x6, 0x13, 0x6e, 0xde, 0x63, 0x8a, 0x5e, 0xa8, 0xc4, 0x9d, 0xa7];
		
		
		let encrypted = match gt.encrypt_ecb(&plain) {
			Ok(x) => x,
			Err(err) => panic!(err)
		};
		assert_eq!(encrypted, expected);
		
		let decrypted = match gt.decrypt_ecb(&encrypted) {
			Ok(x) => x,
			Err(err) => panic!(err)
		};
		assert_eq!(decrypted, plain);	
	}
	
	
}
