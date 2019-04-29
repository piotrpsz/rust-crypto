extern crate rand;


pub mod blowfish;
pub mod gost;
pub mod way3;


/// Converts block of bytes to two u32 words
#[inline]
fn bytes2block(data: &[u8]) -> (u32, u32) {
   let xl = (data[3] as u32).wrapping_shl(24) |
            (data[2] as u32).wrapping_shl(16) |
            (data[1] as u32).wrapping_shl(8)  |
            (data[0] as u32);
   let xr = (data[7] as u32).wrapping_shl(24) |
            (data[6] as u32).wrapping_shl(16) |
            (data[5] as u32).wrapping_shl(8)  |
            (data[4] as u32);
	(xl, xr)
}

fn block2bytes(x: (u32, u32), data: &mut [u8]) {
   words2bytes(x.0, x.1, data);

}
#[inline]
fn words2bytes(xl: u32, xr: u32, data: &mut [u8]) {
   data[3] = xl.wrapping_shr(24) as u8;
   data[2] = xl.wrapping_shr(16) as u8;
   data[1] = xl.wrapping_shr(8)  as u8;
   data[0] = xl as u8;

   data[7] = xr.wrapping_shr(24) as u8;
   data[6] = xr.wrapping_shr(16) as u8;
   data[5] = xr.wrapping_shr(8)  as u8;
   data[4] = xr as u8;
}

pub fn padding(nbytes: usize) -> Vec<u8> {
   let mut s = Vec::with_capacity(nbytes);
	s.resize(nbytes, 0);
   s[0] = 128;
   s
}

pub fn padding_index(data: &[u8]) -> Option<usize> {
	let mut i = data.len();
	
	if i > 0 {
		loop {
			i -= 1;
			let c = data[i];
			if c != 0 {
				if data[i] == 128 {
					return Some(i);
				}
            else {
                break;
            }
			}
	  	}
	}
	None
}
