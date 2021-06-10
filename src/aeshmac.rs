use num::Integer;
use aes::cipher::block_padding::NoPadding;
use aes::cipher::BlockDecryptMut;
use aes::cipher::BlockEncryptMut;
use aes::cipher::KeyIvInit;
use aes::cipher::KeySizeUser;
use digest::{KeyInit};
use encryption::{EType, KeyUsage};
use error::{Error, KerlabErrorKind, KerlabResult};
use hash::hmac_sha1;
use pbkdf2::pbkdf2_hmac;
use sha1::Sha1;
use rand::RngCore;

pub const AES_BLOCK_SIZE: usize = 16;
pub const AES_MAC_SIZE: usize = 12;
pub const AES128_SEED_SIZE: usize = 16;
pub const AES256_SEED_SIZE: usize = 32;

/// Size of AES-128 key, 16 bytes
pub const AES128_KEY_SIZE: usize = 16;

/// Size of AES-256 key, 32 bytes
pub const AES256_KEY_SIZE: usize = 32;

/// Enum to provide asociated parameters with each size of the AES algorithm
pub enum AesSizes {
    Aes128,
    Aes256,
}

impl AesSizes {
    pub fn seed_size(&self) -> usize {
        match &self {
            AesSizes::Aes128 => return AES128_SEED_SIZE,
            AesSizes::Aes256 => return AES256_SEED_SIZE,
        }
    }

    pub fn block_size(&self) -> usize {
        return AES_BLOCK_SIZE;
    }

    pub fn key_size(&self) -> usize {
        match &self {
            AesSizes::Aes128 => return aes::Aes128::key_size(),
            AesSizes::Aes256 => return aes::Aes256::key_size(),
        }
    }

    pub fn mac_size(&self) -> usize {
        return AES_MAC_SIZE;
    }
}

pub fn xorbytes(v1: &[u8], v2: &[u8]) -> Vec<u8> {
    let mut v_xored = Vec::with_capacity(v1.len());

    for i in 0..v1.len() {
        v_xored.push(v1[i] ^ v2[i])
    }

    return v_xored;
}


pub fn pbkdf2_sha1(key: &[u8], salt: &[u8], seed_size: usize) -> Vec<u8> {
    let iteration_count = 0x1000;
    let mut seed: Vec<u8> = vec![0; seed_size];
    pbkdf2_hmac::<Sha1>(key, salt, iteration_count, &mut seed);
    return seed;
}

type Aes128EcbDec = ecb::Decryptor<aes::Aes128>;
type Aes256EcbDec = ecb::Decryptor<aes::Aes256>;

pub fn decrypt_aes_ecb(
    key: &[u8],
    ciphertext: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    match aes_sizes {
        AesSizes::Aes128 => Aes128EcbDec::new(key.into())
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .unwrap(),
        AesSizes::Aes256 => Aes256EcbDec::new(key.into())
            .decrypt_padded_vec_mut::<NoPadding>(ciphertext)
            .unwrap(),
    }
}

type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes256CbcEnc = cbc::Encryptor<aes::Aes256>;

pub fn encrypt_aes_cbc(
    key: &[u8],
    plaintext: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    let iv = [0; AES_BLOCK_SIZE];
    match aes_sizes {
        AesSizes::Aes128 => Aes128CbcEnc::new(key.into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(plaintext),
        AesSizes::Aes256 => Aes256CbcEnc::new(key.into(), &iv.into())
            .encrypt_padded_vec_mut::<NoPadding>(plaintext),
    }
}
pub fn dk(key: &[u8], constant: &[u8], aes_sizes: &AesSizes) -> Vec<u8> {
    let mut plaintext = n_fold(constant, aes_sizes.block_size());
    let mut result: Vec<u8> = Vec::new();

    while result.len() < aes_sizes.seed_size() {
        plaintext = encrypt_aes_cbc(key, &plaintext, aes_sizes);
        result.append(&mut plaintext.clone());
    }

    return result;
}

pub fn n_fold(v: &[u8], nbytes: usize) -> Vec<u8> {
    let data_13_series = generate_13_bits_rotations_serie(v, nbytes);
    let nbytes_chunks = divide_in_exact_n_bytes_chunks(&data_13_series, nbytes);
    add_chunks_with_1s_complement_addition(&nbytes_chunks)
}

fn generate_13_bits_rotations_serie(v: &[u8], nbytes: usize) -> Vec<u8> {
    let least_common_multiple = nbytes.lcm(&v.len());
    let mut big_v: Vec<u8> = Vec::new();

    for i in 0..(least_common_multiple / v.len()) {
        let mut v_rotate = rotate_rigth_n_bits(v, 13 * i);
        big_v.append(&mut v_rotate);
    }

    big_v
}

fn rotate_rigth_n_bits(v: &[u8], nbits: usize) -> Vec<u8> {
    let nbytes = nbits / 8 % v.len();
    let nbits_remain = nbits % 8;

    let mut v_rotate: Vec<u8> = Vec::with_capacity(v.len());

    for i in 0..v.len() {
        let index_a = (((i as i32 - nbytes as i32) % v.len() as i32)
            + v.len() as i32) as usize
            % v.len();
        let index_b = (((i as i32 - nbytes as i32 - 1) % v.len() as i32)
            + v.len() as i32) as usize
            % v.len();

        v_rotate.push(
            (((v[index_a] as u16) >> nbits_remain) as u8)
                | (((v[index_b] as u16) << (8 - nbits_remain)) as u8),
        );
    }

    v_rotate
}

fn divide_in_exact_n_bytes_chunks(v: &[u8], nbytes: usize) -> Vec<Vec<u8>> {
    let mut nbytes_chunks: Vec<Vec<u8>> = Vec::new();

    let mut i = 0;
    while i < v.len() {
        nbytes_chunks.push(v[i..i + nbytes].to_vec());
        i += nbytes;
    }

    nbytes_chunks
}

fn add_chunks_with_1s_complement_addition(chunks: &[Vec<u8>]) -> Vec<u8> {
    let mut result = chunks[0].clone();
    for chunk in chunks[1..].iter() {
        result = add_chunk_with_1s_complement(&result, chunk);
    }
    result
}

fn add_chunk_with_1s_complement(chunk_1: &[u8], chunk_2: &[u8]) -> Vec<u8> {
    let mut tmp_add = add_chunks_as_u16_vector(chunk_1, chunk_2);

    while tmp_add.iter().any(|&x| x > 0xff) {
        propagate_carry_bits(&mut tmp_add);
    }

    convert_u16_vector_to_u8_vector(&tmp_add)
}

fn add_chunks_as_u16_vector(chunk_1: &[u8], chunk_2: &[u8]) -> Vec<u16> {
    let mut tmp_add: Vec<u16> = vec![0; chunk_1.len()];

    for j in 0..chunk_1.len() {
        tmp_add[j] = chunk_1[j] as u16 + chunk_2[j] as u16;
    }

    tmp_add
}

fn propagate_carry_bits(tmp_add: &mut [u16]) {
    let mut aux_vector: Vec<u16> = vec![0; tmp_add.len()];

    for i in 0..tmp_add.len() {
        let index = (((i as i32 - tmp_add.len() as i32 + 1)
            % tmp_add.len() as i32)
            + tmp_add.len() as i32) as usize
            % tmp_add.len();
        aux_vector[i] = (tmp_add[index] >> 8) + (tmp_add[i] & 0xff)
    }
    tmp_add.copy_from_slice(&aux_vector[..tmp_add.len()]);
}

fn convert_u16_vector_to_u8_vector(v: &[u16]) -> Vec<u8> {
    v.iter().map(|&x| x as u8).collect()
}

/// Encrypt plaintext by using the AES algorithm with HMAC-SHA1
pub fn encrypt(
    key: &[u8],
    key_usage: i32,
    plaintext: &[u8],
    preamble: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    let (ki, ke) = generate_ki_ke(key, key_usage, aes_sizes);

    let mut basic_plaintext = preamble.to_vec();
    basic_plaintext.append(&mut plaintext.to_vec());

    let hmac = hmac_sha1(&ki, &basic_plaintext);

    let mut ciphertext = basic_encrypt(&ke, &basic_plaintext, aes_sizes);
    ciphertext.append(&mut hmac[..aes_sizes.mac_size()].to_vec());

    ciphertext
}

fn basic_encrypt(
    key: &[u8],
    plaintext: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    let block_size = aes_sizes.block_size();
    let pad_length = (block_size - (plaintext.len() % block_size)) % block_size;

    let mut padded_plaintext = plaintext.to_vec();
    padded_plaintext.append(&mut vec![0; pad_length]);

    let ciphertext = encrypt_aes_cbc(key, &padded_plaintext, aes_sizes);

    if ciphertext.len() <= block_size {
        return ciphertext;
    }

    let mut swapped_ciphertext = Vec::with_capacity(ciphertext.len());
    let mut end_no_lasts_blocks_index = 0;
    if ciphertext.len() > (block_size * 2) {
        end_no_lasts_blocks_index = ciphertext.len() - (block_size * 2);
        let mut no_lasts_blocks =
            (ciphertext[..end_no_lasts_blocks_index]).to_vec();
        swapped_ciphertext.append(&mut no_lasts_blocks);
    }

    let real_last_block_length = block_size - pad_length;

    let second_last_block = ciphertext
        [end_no_lasts_blocks_index..(end_no_lasts_blocks_index + block_size)]
        .to_vec();
    let mut last_block =
        ciphertext[(end_no_lasts_blocks_index + block_size)..].to_vec();

    let mut second_last_block_real_portion =
        second_last_block[..real_last_block_length].to_vec();

    swapped_ciphertext.append(&mut last_block);
    swapped_ciphertext.append(&mut second_last_block_real_portion);

    swapped_ciphertext
}

/// Decrypt ciphertext by using the AES algorithm with HMAC-SHA1
pub fn decrypt(
    key: &[u8],
    key_usage: i32,
    ciphertext: &[u8],
    aes_sizes: &AesSizes,
) -> KerlabResult<Vec<u8>> {
    let (ki, ke) = generate_ki_ke(key, key_usage, aes_sizes);

    if ciphertext.len() < aes_sizes.block_size() + aes_sizes.mac_size() {
        Err(Error::new(KerlabErrorKind::Crypto, "Ciphertext too short"))?
    }

    let ciphertext_end_index = ciphertext.len() - aes_sizes.mac_size();
    let pure_ciphertext = &ciphertext[0..ciphertext_end_index];
    let mac = &ciphertext[ciphertext_end_index..];

    let plaintext = basic_decrypt(&ke, pure_ciphertext, aes_sizes)?;

    let calculated_mac = hmac_sha1(&ki, &plaintext);

    if calculated_mac[..aes_sizes.mac_size()] != mac[..] {
        Err(Error::new(KerlabErrorKind::Crypto, "Hmac integrity failure"))?
    }

    Ok(plaintext[aes_sizes.block_size()..].to_vec())
}

fn basic_decrypt(
    key: &[u8],
    ciphertext: &[u8],
    aes_sizes: &AesSizes,
) -> KerlabResult<Vec<u8>> {
    if ciphertext.len() == aes_sizes.block_size() {
        let plaintext = decrypt_aes_ecb(key, ciphertext, aes_sizes);
        return Ok(plaintext);
    }

    let blocks = divide_in_n_bytes_blocks(ciphertext, aes_sizes.block_size());

    let second_last_index = blocks.len() - 2;

    let (mut plaintext, previous_block) = decrypt_several_blocks_xor_aes_ecb(
        key,
        &blocks[0..second_last_index],
        aes_sizes,
    );

    let mut last_plaintext = decrypt_last_two_blocks(
        key,
        &blocks[second_last_index..],
        &previous_block,
        aes_sizes,
    );

    plaintext.append(&mut last_plaintext);

    Ok(plaintext)
}

fn generate_ki_ke(
    key: &[u8],
    key_usage: i32,
    aes_sizes: &AesSizes,
) -> (Vec<u8>, Vec<u8>) {
    let key_usage_bytes = key_usage.to_be_bytes();

    let mut ki_seed = key_usage_bytes.to_vec();
    ki_seed.push(0x55);

    let mut ke_seed = key_usage_bytes.to_vec();
    ke_seed.push(0xaa);

    let ki = dk(key, &ki_seed, aes_sizes);
    let ke = dk(key, &ke_seed, aes_sizes);

    (ki, ke)
}

fn divide_in_n_bytes_blocks(v: &[u8], nbytes: usize) -> Vec<Vec<u8>> {
    let mut blocks: Vec<Vec<u8>> = Vec::new();

    let mut i = 0;
    while i < v.len() {
        let mut j = i + nbytes;
        if j > v.len() {
            j = v.len();
        }

        blocks.push(v[i..j].to_vec());
        i += nbytes;
    }

    return blocks;
}

fn decrypt_several_blocks_xor_aes_ecb(
    key: &[u8],
    blocks: &[Vec<u8>],
    aes_sizes: &AesSizes,
) -> (Vec<u8>, Vec<u8>) {
    let mut plaintext: Vec<u8> = Vec::new();
    let mut previous_block = vec![0; aes_sizes.block_size()];

    for block in blocks.iter() {
        let mut block_plaintext = decrypt_aes_ecb(key, block, aes_sizes);
        block_plaintext = xorbytes(&block_plaintext, &previous_block);

        plaintext.append(&mut block_plaintext);
        previous_block.clone_from(block);
    }

    (plaintext, previous_block)
}

fn decrypt_last_two_blocks(
    key: &[u8],
    blocks: &[Vec<u8>],
    previous_block: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    let second_last_block_plaintext =
        decrypt_aes_ecb(key, &blocks[0], aes_sizes);

    let last_block_length = blocks[1].len();
    let mut last_block = blocks[1].to_vec();

    let mut last_plaintext = xorbytes(
        &second_last_block_plaintext[0..last_block_length],
        &last_block,
    );

    let mut omitted = second_last_block_plaintext[last_block_length..].to_vec();

    last_block.append(&mut omitted);

    let last_block_plaintext = decrypt_aes_ecb(key, &last_block, aes_sizes);

    let mut plaintext = Vec::new();
    plaintext.append(&mut xorbytes(&last_block_plaintext, previous_block));
    plaintext.append(&mut last_plaintext);

    plaintext
}

pub fn aes_generate_key(
    passphrase: &[u8],
    salt: &[u8],
    aes_sizes: &AesSizes,
) -> Vec<u8> {
    let key = pbkdf2_sha1(passphrase, salt, aes_sizes.seed_size());
    dk(&key, "kerberos".as_bytes(), aes_sizes)
}

pub fn aes_generate_salt(realm: &str, username: &str) -> Vec<u8> {
    let mut salt = realm.to_uppercase();
    let mut lowercase_username = username.to_string();

    if lowercase_username.ends_with('$') {
        // client name = "host<client_name>.lower.domain.com"
        salt.push_str("host");
        lowercase_username.pop();
        salt.push_str(&lowercase_username);
        salt.push('.');
        salt.push_str(&realm.to_lowercase());
    } else {
        salt.push_str(&lowercase_username);
    }

    salt.as_bytes().to_vec()
}

fn random_bytes(size: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let mut bytes: Vec<u8> = vec![0; size];
    rng.fill_bytes(&mut bytes);

    return bytes;
}


fn generate_preamble(aes_sizes: &AesSizes) -> Vec<u8> {
    random_bytes(aes_sizes.block_size())
}


pub struct Aes {
    key: Vec<u8>,
    usage: KeyUsage,
    size: AesSizes
}

impl Aes {
    pub fn new(key: Vec<u8>, usage: KeyUsage, size: AesSizes) -> Self {
        Self {
            key,
            usage,
            size
        }
    }

    pub fn etype(&self) -> EType {
        match self.size {
            AesSizes::Aes128 => EType::Aes128CtsHmacSha196,
            AesSizes::Aes256 => EType::Aes256CtsHmacSha196
        }
    }

    pub fn encrypt(&mut self, data: &[u8]) -> KerlabResult<Vec<u8>> {
        Ok(encrypt(&self.key, self.usage as i32, data, &generate_preamble(&AesSizes::Aes256), &self.size))
    }

    pub fn decrypt(&mut self, data: &[u8]) -> KerlabResult<Vec<u8>> {
        decrypt(&self.key, self.usage as i32, data, &self.size)
    }
}