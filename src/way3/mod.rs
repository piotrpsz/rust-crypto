// use padding;
// use padding_index;

const KEY_SIZE: usize = 12;
// const BLOC_KSIZE: usize = 12;
const NMBR: usize = 11;
const ERCON: [u32; 12] = [0x0b0b, 0x1616, 0x2c2c, 0x5858, 0xb0b0, 0x7171, 0xe2e2, 0xd5d5, 0xbbbb, 0x6767, 0xcece, 0x8d8d]; 
const DRCON: [u32; 12] = [0xb1b1, 0x7373, 0xe6e6, 0xdddd, 0xabab, 0x4747, 0x8e8e, 0x0d0d, 0x1a1a, 0x3434, 0x6868, 0xd0d0];

pub struct Way3 {
	k:  (u32, u32, u32),
	ki: (u32, u32, u32),
}

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