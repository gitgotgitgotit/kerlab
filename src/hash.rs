use hmac::{Hmac, Mac};
use md5::Md5;
use sha1::Sha1;

type HmacMd5 = Hmac<Md5>;

pub fn hmac_md5(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmacker = HmacMd5::new_from_slice(key).unwrap();
    hmacker.update(data);
    hmacker.finalize().into_bytes().to_vec()
}

type HmacSha1 = Hmac<Sha1>;

pub fn hmac_sha1(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut hmacker = HmacSha1::new_from_slice(key).unwrap();
    hmacker.update(data);
    hmacker.finalize().into_bytes().to_vec()
}

