/*
* Module: 3way
* Autor: Piotr Pszczółkowski (piotr@beesoft.pl)
* Date: 5/05/2019
*
* Copyright (c) 2019, Piotr Pszczółkowski
* All rights reserved.
* 
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice, this
*    list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
* AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
* DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
* SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
* CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
* OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

use padding;
use padding_index;
use rand::Rng;

const KEY_SIZE: usize = 12;
const BLOCK_SIZE: usize = 12;
const NMBR: usize = 11;
const ERCON: [u32; 12] = [0x0b0b, 0x1616, 0x2c2c, 0x5858, 0xb0b0, 0x7171, 0xe2e2, 0xd5d5, 0xbbbb, 0x6767, 0xcece, 0x8d8d]; 
const DRCON: [u32; 12] = [0xb1b1, 0x7373, 0xe6e6, 0xdddd, 0xabab, 0x4747, 0x8e8e, 0x0d0d, 0x1a1a, 0x3434, 0x6868, 0xd0d0];

pub struct Way3 {
	k:  (u32, u32, u32),
	ki: (u32, u32, u32),
}

/// Creates new Way3 object initialised with passed 'key'.
pub fn new(key: &[u8]) -> Result<Way3, String> {
	if key.len() != KEY_SIZE {
		return Err("invalid key size".to_string())
	}

	let k = bytes3block(key);
	let ki = mu(theta(k));
	
	let w3 = Way3{k, ki};
	Ok(w3)
}


impl Way3 {
	
	/// encrypts 'input' in CBC mode random generated iv.
	pub fn encrypt_cbc(&self, input: &Vec<u8>) -> Result<Vec<u8>, String> {
		self.encrypt_cbc_iv(input, {
			let mut buffer = [0u8; BLOCK_SIZE];
			rand::thread_rng().fill(&mut buffer);
			&buffer.to_vec()
		})
	}
	
	/// encrypts 'input' in CBC mode using 'iv'.
	pub fn encrypt_cbc_iv(&self, input: &Vec<u8>, iv: &Vec<u8>) -> Result<Vec<u8>, String> {
		// handle caller mistakes
		if iv.len() != BLOCK_SIZE { return Err("invalid iv size".to_string()) }
		if input.len() == 0 { return Err("nothing to encrypt".to_string()) }
		
		// create plain text buffer from 'input',
		// with padding if needed
		let plain = {
         let mut buffer: Vec<u8> = Vec::new();
         buffer.extend(input);
         let n = buffer.len() % BLOCK_SIZE;
         if n != 0 {
            buffer.extend(padding(BLOCK_SIZE - n));
         }
         buffer
		};
      let nbytes = plain.len();
		
		// create cipher text buffer
		// the first block initialised with 'iv' content
		let mut cipher = {
			let mut buffer = Vec::new();
			buffer.resize(nbytes + BLOCK_SIZE, 0);
         buffer[0..BLOCK_SIZE].copy_from_slice(iv);
			buffer
		};
		
		let mut i = 0usize;
		let mut c = bytes3block(iv);
		while i < nbytes {
			let t = bytes3block(&plain[i..]);
			c = self.encrypt((t.0 ^ c.0, t.1 ^ c.1, t.2 ^ c.2));
			block3bytes(c, &mut cipher[(i + BLOCK_SIZE)..]);
			i += BLOCK_SIZE;
		}
		
		Ok(cipher)
	}
	
	/// decrypts 'cipher' in CBC mode
	pub fn decrypt_cbc(&self, cipher: &Vec<u8>) -> Result<Vec<u8>, String> {
 		let nbytes = cipher.len();
		if nbytes <= BLOCK_SIZE { return  Err("cipher data size is to short".to_string()) }
		if (nbytes % BLOCK_SIZE) != 0 { return Err("cipher data size is wrong".to_string()) }
		
		let mut plain: Vec<u8> = Vec::new();
      plain.resize(nbytes - BLOCK_SIZE, 0);
		
		
		let mut p = bytes3block(&cipher[..]);
		let mut i = BLOCK_SIZE;
		while i < nbytes {
			let a = bytes3block(&cipher[i..]);
			let t = a;
			let c = self.decrypt(a);
			block3bytes((c.0 ^ p.0, c.1 ^ p.1, c.2 ^ p.2), &mut plain[(i - BLOCK_SIZE)..]);
			p = t;
			i += BLOCK_SIZE;
		}
		
		match padding_index(&plain) {
			Some(idx) => {
            let retv = plain[..idx].to_vec();
				Ok(retv)
			},
			_ => {
				Ok(plain)
			}
		}
	}
	
	
	
	pub fn encrypt_ecb(&self, input: &Vec<u8>) -> Result<Vec<u8>, String> {
		if input.len() == 0 { return Err("plain text size is 0".to_string()) }
		
		let plain = {
			let mut buffer = Vec::new();
			buffer.extend(input);
			let n = buffer.len() % BLOCK_SIZE;
			if n != 0 {
				buffer.extend(padding(BLOCK_SIZE - n));
			}
			buffer
		};
		let nbytes = plain.len();
		
		let mut cipher = Vec::with_capacity(nbytes);
		cipher.resize(nbytes, 0);
		
		let mut i = 0usize;
		while i < nbytes {
			let p = bytes3block(&plain[i..]);
			let c = self.encrypt(p);
			block3bytes(c, &mut cipher[i..]);
			i += BLOCK_SIZE;
		}
		
		Ok(cipher)
	}
	
	pub fn decrypt_ecb(&self, cipher: &Vec<u8>) -> Result<Vec<u8>, String> {
		let nbytes = cipher.len();
		if nbytes == 0 { return Err("cipher text size is 0".to_string()) }
		if (nbytes % BLOCK_SIZE) != 0 { return Err("invalid cipher text size".to_string()) }
		
		let mut plain = Vec::with_capacity(nbytes);
		plain.resize(nbytes, 0);
		
		let mut i = 0usize;
		while i < nbytes {
			let c = bytes3block(&cipher[i..]);
			let p = self.decrypt(c);
			block3bytes(p, &mut plain[i..]);
			i += BLOCK_SIZE;
		}
		
		match padding_index(&plain) {
			Some(idx) => Ok(plain[..idx].to_vec()),
			_ => Ok(plain)
		}
	}
	
	pub fn encrypt(&self, mut x: (u32, u32, u32)) -> (u32, u32, u32) {
		let mut i = 0usize;
		
		while i < NMBR {
			x.0 ^= self.k.0 ^ ERCON[i].wrapping_shl(16);
			x.1 ^= self.k.1;
			x.2 ^= self.k.2 ^ ERCON[i];
			x = rho(x);
			i += 1;
		}
		
		x.0 ^= self.k.0 ^ ERCON[NMBR].wrapping_shl(16);
		x.1 ^= self.k.1;
		x.2 ^= self.k.2 ^ ERCON[NMBR];
		
		theta(x)
	}
	
	
	pub fn decrypt(&self, mut x: (u32, u32, u32)) -> (u32, u32, u32) {
		let mut i = 0usize;
		
		x = mu(x);
		while i < NMBR {
			x.0 ^= self.ki.0 ^ DRCON[i].wrapping_shl(16);
			x.1 ^= self.ki.1;
			x.2 ^= self.ki.2 ^ DRCON[i];
			x = rho(x);
			i += 1;
		}
		
		x.0 ^= self.ki.0 ^ DRCON[NMBR].wrapping_shl(16);
		x.1 ^= self.ki.1;
		x.2 ^= self.ki.2 ^ DRCON[NMBR];
		
		mu(theta(x))
	}
	
}

#[cfg(test)]
mod tests {
	use super::*;
	
	#[test]
	fn test_block_111() {
		let key = vec![0x0u8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0];
		let w3 = new(&key).unwrap();
		
		let x = (1u32, 1u32, 1u32);
		let e = (0x4059c76eu32, 0x83ae9dc4u32, 0xad21ecf7u32);
		
		let a = w3.encrypt(x);
		assert_eq!(a, e);
		
		let d = w3.decrypt(a);
		assert_eq!(d, x);
	}
	
	#[test]
	fn test_block_321() {
		let key = vec![0x6u8, 0x0, 0x0, 0x0, 0x5, 0x0, 0x0, 0x0, 0x4, 0x0, 0x0, 0x0];
		let w3 = new(&key).unwrap();
		
		let x = (3u32, 2u32, 1u32);
		let e = (0xd2f05b5eu32, 0xd6144138u32, 0xcab920cdu32);
		
		let a = w3.encrypt(x);
		assert_eq!(a, e);
		
		let d = w3.decrypt(a);
		assert_eq!(d, x);
	}
	
	#[test]
	fn test_block_mix() {
		let key = vec![0x34u8, 0x12, 0xf0, 0xde, 0xab, 0x89, 0x67, 0x45, 0x12, 0xf0, 0xde, 0xbc];
		let w3 = new(&key).unwrap();
		
		let x = (0x23456789u32, 0x9abcdef0u32, 0x01234567u32);
		let e = (0x0aa55dbbu32, 0x9cdddb6du32, 0x7cdb76b2u32);
		
		let a = w3.encrypt(x);
		assert_eq!(a, e);
		
		let d = w3.decrypt(a);
		assert_eq!(d, x);
	}
	
	#[test]
	fn test_ecb() {
		let key = vec![0x5eu8, 0x5b, 0xf0, 0xd2, 0x38, 0x41, 0x14, 0xd6, 0xcd, 0x20, 0xb9, 0xca];
		let w3 = new(&key).unwrap();
		
		let plain = "Artur, Błazej, Jolanta, Piotr Pszczółkowski".as_bytes().to_vec();
		
		let encrypted = match w3.encrypt_ecb(&plain) {
			Ok(x) => x,
			Err(err) => panic!(err)
		};

		let decrypted = match w3.decrypt_ecb(&encrypted) {
			Ok(x) => x,
			Err(err) => panic!(err)
		};
		assert_eq!(decrypted, plain);	
		
	}

	#[test]
	fn test_cbc_iv() {
		let key = vec![0x5eu8, 0x5b, 0xf0, 0xd2, 0x38, 0x41, 0x14, 0xd6, 0xcd, 0x20, 0xb9, 0xca];
		let iv = b"123456789012".to_vec();
		let expected = vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x30, 0x31,
		                    0x32, 0xf2, 0x33, 0x56, 0x75, 0x26, 0xd9, 0xa0, 0xd4, 0x9d, 0x73,
								  0x8d, 0x51, 0x42, 0x26, 0x10, 0x6e, 0x2d, 0xfb, 0xef, 0xc5, 0x68,
								  0x27, 0x99, 0x48, 0x5b, 0xb5, 0x8, 0xc6, 0xd7, 0xdc, 0xbc, 0x27,
								  0xfa, 0xa7, 0x2f, 0x96, 0xfc, 0xae, 0x35, 0xe4, 0xf9, 0x65, 0xb5,
								  0x9e, 0x41, 0x11, 0x6e, 0xcf];
		
		let w3 = new(&key).unwrap();
		
		let plain = "Artur, Błazej, Jolanta, Piotr Pszczółkowski".as_bytes().to_vec();
		
		let encrypted = match w3.encrypt_cbc_iv(&plain, &iv) {
			Ok(x) => x,
			Err(err) => panic!(err)
		};
		assert_eq!(encrypted, expected);

		let decrypted = match w3.decrypt_cbc(&encrypted) {
			Ok(x) => x,
			Err(err) => panic!(err)
		};
		assert_eq!(decrypted, plain);	
	}
	
	#[test]
	fn test_cbc() {
		let key = vec![0x5eu8, 0x5b, 0xf0, 0xd2, 0x38, 0x41, 0x14, 0xd6, 0xcd, 0x20, 0xb9, 0xca];
		let w3 = new(&key).unwrap();
		let plain = b"Yamato & Musashi".to_vec();

		match w3.encrypt_cbc(&plain) {
			Ok(encrypted) => {
				match w3.decrypt_cbc(&encrypted) {
					Ok(decrypted) => {
						assert_eq!(decrypted, plain);
					},
					Err(err) => panic!(err)
				}
			},
			Err(err) => panic!(err)
		};
		
	}
}

fn mu(mut x: (u32, u32, u32)) -> (u32, u32, u32) {
	let mut w = (0u32, 0u32, 0u32);
	let mut i = 0usize;
	
	while i < 32 {
		w.0 <<= 1;
		w.1 <<= 1;
		w.2 <<= 1;
		
		w.0 |= x.2 & 0x1;
		w.1 |= x.1 & 0x1;
		w.2 |= x.0 & 0x1;
		
		x.0 >>= 1;
		x.1 >>= 1;
		x.2 >>= 1;
		
		i += 1;
	}
	
	w
}

fn gamma(x: (u32, u32, u32)) -> (u32, u32, u32) {
	let w0 = (!x.0) ^ ((!x.1) & x.2);
	let w1 = (!x.1) ^ ((!x.2) & x.0);
	let w2 = (!x.2) ^ ((!x.0) & x.1);
	
	(w0, w1, w2)
}

fn theta(x: (u32, u32, u32)) -> (u32, u32, u32) {
	let w0 = x.0 ^
				x.0.wrapping_shr(16) ^ x.1.wrapping_shl(16) ^
				x.1.wrapping_shr(16) ^ x.2.wrapping_shl(16) ^
				x.1.wrapping_shr(24) ^ x.2.wrapping_shl( 8) ^
				x.2.wrapping_shr( 8) ^ x.0.wrapping_shl(24) ^
				x.2.wrapping_shr(16) ^ x.0.wrapping_shl(16) ^
				x.2.wrapping_shr(24) ^ x.0.wrapping_shl( 8);
	let w1 = x.1 ^
				x.1.wrapping_shr(16) ^ x.2.wrapping_shl(16) ^
				x.2.wrapping_shr(16) ^ x.0.wrapping_shl(16) ^
				x.2.wrapping_shr(24) ^ x.0.wrapping_shl( 8) ^
				x.0.wrapping_shr( 8) ^ x.1.wrapping_shl(24) ^
				x.0.wrapping_shr(16) ^ x.1.wrapping_shl(16) ^
				x.0.wrapping_shr(24) ^ x.1.wrapping_shl( 8);
	let w2 = x.2 ^
				x.2.wrapping_shr(16) ^ x.0.wrapping_shl(16) ^
				x.0.wrapping_shr(16) ^ x.1.wrapping_shl(16) ^
				x.0.wrapping_shr(24) ^ x.1.wrapping_shl( 8) ^
				x.1.wrapping_shr( 8) ^ x.2.wrapping_shl(24) ^
				x.1.wrapping_shr(16) ^ x.2.wrapping_shl(16) ^
				x.1.wrapping_shr(24) ^ x.2.wrapping_shl( 8);
	
	(w0, w1, w2)
}

fn pi_1(x: (u32, u32, u32)) -> (u32, u32, u32) {
	let w0 = x.0.wrapping_shr(10) ^ x.0.wrapping_shl(22);
	let w1 = x.1;
	let w2 = x.2.wrapping_shl(1) ^ x.2.wrapping_shr(31);
	
	(w0, w1, w2)
}

fn pi_2(x: (u32, u32, u32)) -> (u32, u32, u32) {
	let w0 = x.0.wrapping_shl(1) ^ x.0.wrapping_shr(31);
	let w1 = x.1;
	let w2 = x.2.wrapping_shr(10) ^ x.2.wrapping_shl(22);
	
	(w0, w1, w2)
}

fn rho(x: (u32, u32, u32)) -> (u32, u32, u32) {
	pi_2(gamma(pi_1(theta(x))))
}


fn bytes3block(data: &[u8]) -> (u32, u32, u32) {
	let w0 = (data[3] as u32).wrapping_shl(24) |
				(data[2] as u32).wrapping_shl(16) |
				(data[1] as u32).wrapping_shl(8)  |
				(data[0] as u32);
	let w1 = (data[7] as u32).wrapping_shl(24) |
				(data[6] as u32).wrapping_shl(16) |
				(data[5] as u32).wrapping_shl(8)  |
				(data[4] as u32);
	let w2 = (data[11] as u32).wrapping_shl(24) |
				(data[10] as u32).wrapping_shl(16) |
				(data[9] as u32).wrapping_shl(8)   |
				(data[8] as u32);
	
	(w0, w1, w2)
}


fn block3bytes(x: (u32, u32, u32), data: &mut [u8]) {
	data[3]  = (x.0.wrapping_shr(24) & 0xff) as u8;
	data[2]  = (x.0.wrapping_shr(16) & 0xff) as u8;
	data[1]  = (x.0.wrapping_shr(8) & 0xff) as u8;
	data[0]  = (x.0 & 0xff) as u8;
	
	data[7]  = (x.1.wrapping_shr(24) & 0xff) as u8;
	data[6]  = (x.1.wrapping_shr(16) & 0xff) as u8;
	data[5]  = (x.1.wrapping_shr(8) & 0xff) as u8;
	data[4]  = (x.1 & 0xff) as u8;

	data[11] = (x.2.wrapping_shr(24) & 0xff) as u8;
	data[10] = (x.2.wrapping_shr(16) & 0xff) as u8;
	data[9]  = (x.2.wrapping_shr(8) & 0xff) as u8;
	data[8]  = (x.2 & 0xff) as u8;
}