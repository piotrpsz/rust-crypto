extern crate rand;


pub mod blowfish;
pub mod gost;

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
