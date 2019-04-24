extern crate crypto;

fn main() {
    // let plain = "Włodzimierz Piotr Pszczółkowski".as_bytes().to_vec();
    // let iv = vec![0x80, 0x8b, 0x22, 0xd1, 0xe4, 0xbc, 0x79, 0x67];
    // let key = "TESTKEY".as_bytes();
    // let bf = crypto::blowfish::new(&key);
    
    // match bf.encrypt_cbc_iv(&plain, &iv) {
    //     Ok(encrypted) => {
    //         println!("Encrypted:\n{:02x?}", encrypted);
    //         // match bf.decrypt_cbc(&encrypted) {
    //         //     Ok(_decrypted) => {
    //         //         //println!("Decrypted:\n{:?}", decrypted);
    //         //         //println!("       iv: {:x?}", iv);
    //         //         //println!("      txt: {:?}", unsafe {String::from_utf8_unchecked(decrypted)});
    //         //     },
    //         //     Err(err) => panic!("CBC decryption: {:?}", err)
    //         // }
    //     },
    //     Err(err) => panic!("CBC encryption: {:?}", err)
    // }
}