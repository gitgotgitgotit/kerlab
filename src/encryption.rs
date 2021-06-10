use std::convert::TryFrom;
use asn1::{ASN1, Tag, Integer, OctetString, to_der, from_ber};
use error::{KerlabResult, Error, KerlabErrorKind};
use yasna::{DERWriter, BERReader};
use aeshmac::{aes_generate_key, aes_generate_salt, Aes, AesSizes};
use rc4hmac::Rc4Hmac;
use ntlm::{ntlm};


#[repr(u32)]
pub enum EType {
    NoEncryption = 0,
    DesCbcCrc = 1,
    DesCbcMd5 = 3,
    Aes256CtsHmacSha196 = 18,
    Aes128CtsHmacSha196 = 17,
    Rc4Hmac = 23,
    Rc4HmacExp = 24
}

impl TryFrom<u32> for EType {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(EType::NoEncryption),
            1 => Ok(EType::DesCbcCrc),
            3 => Ok(EType::DesCbcMd5),
            18 => Ok(EType::Aes256CtsHmacSha196),
            17 => Ok(EType::Aes128CtsHmacSha196),
            23 => Ok(EType::Rc4Hmac),
            24 => Ok(EType::Rc4HmacExp),
            _ => Err(Error::new(KerlabErrorKind::Crypto, "Unknown algorithm"))
        }
    }
}

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum KeyUsage {
    KeyUsageAsReqTimestamp = 1,
    KeyUsageAsRepTicket = 2,
    KeyUsageAsRepEncPart1 = 3,
    KrbKeyUsageTgsReqPaAuthenticator = 7,
    KeyUsageAsRepEncPart = 8
}


/// @see https://www.freesoft.org/CIE/RFC/1510/70.htm
/// ```asn.1
/// EncryptedData   ::= SEQUENCE {
///        etype   [0] INTEGER -- EncryptionType --,
///        kvno    [1] INTEGER OPTIONAL,
///        cipher  [2] OCTET STRING -- ciphertext
/// }
/// ```

#[derive(Sequence, PartialEq, Clone, Default)]
pub struct EncryptedData {
    pub etype: Tag<0, Integer>,
    pub kvno: Option<Tag<1, Integer>>,
    pub cipher: Tag<2, OctetString>
}

impl EncryptedData {
    pub fn new(etype: Integer, cipher: OctetString) -> Self {
        Self {
            etype: Tag::new(etype),
            kvno: None,
            cipher: Tag::new(cipher)
        }
    }

    /// Conveninent function to decrypt a blob as an ASN.1 defined structure
    pub fn decrypt_as<T: ASN1 + Default>(&self, password: &str, key_usage: KeyUsage) -> KerlabResult<T> {
        match EType::try_from(self.etype.inner)? {
            EType::NoEncryption => {
                let mut result = T::default();
                from_ber(&mut result, &self.cipher.inner)?;
                Ok(result)
            },
            EType::Rc4Hmac => {
                let plaintext = Rc4Hmac::new(ntlm(password)?, key_usage).decrypt(&self.cipher.inner)?;
                let mut result = T::default();
                from_ber(&mut result, &plaintext)?;
                Ok(result)
            },
            EType::Aes128CtsHmacSha196 => {
                let plaintext = Aes::new(ntlm(password)?, key_usage, AesSizes::Aes128).decrypt(&self.cipher.inner)?;
                let mut result = T::default();
                from_ber(&mut result, &plaintext)?;
                Ok(result)
            },
            EType::Aes256CtsHmacSha196 => {
                let plaintext = Aes::new(ntlm(password)?, key_usage, AesSizes::Aes128).decrypt(&self.cipher.inner)?;
                let mut result = T::default();
                from_ber(&mut result, &plaintext)?;
                Ok(result)
            }
            _ => Err(Error::new(KerlabErrorKind::Crypto, "Unsupported Algorithm"))
        }
    }
}

/// @see https://www.freesoft.org/CIE/RFC/1510/71.htm
/// ```asn.1
/// EncryptionKey ::=   SEQUENCE {
///       keytype[0]    INTEGER,
///       keyvalue[1]   OCTET STRING
/// }
#[derive(Sequence, PartialEq, Default, Clone)]
pub struct EncryptionKey {
    pub keytype: Tag<0, Integer>,
    pub keyvalue: Tag<1, OctetString>
}

impl EncryptionKey {
    pub fn new(keytype: EType, keyvalue: OctetString) -> Self {
        Self {
            keytype: Tag::new(keytype as Integer),
            keyvalue: Tag::new(keyvalue)
        }
    }

    pub fn new_no_encryption() -> KerlabResult<Self> {
        Ok(Self {
            keytype: Tag::new(EType::NoEncryption as Integer),
            keyvalue: Tag::new(vec![])
        })
    }

    pub fn new_rc4_hmac(password: &str) -> KerlabResult<Self> {
        Ok(Self {
            keytype: Tag::new(EType::Rc4Hmac as Integer),
            keyvalue: Tag::new(ntlm(password)?)
        })
    }

    pub fn new_rc4_hmac_from_hash(hash: Vec<u8>) -> KerlabResult<Self> {
        Ok(Self {
            keytype: Tag::new(EType::Rc4Hmac as Integer),
            keyvalue: Tag::new(hash)
        })
    }

    pub fn new_aes128_hmac(realm: &str, username: &str, password: &str) -> KerlabResult<Self> {
        println!("{:?} {:?} {:?} {:?} {:?}", realm, username, password, String::from_utf8(aes_generate_salt(realm, username)), aes_generate_key(password.as_bytes(), &aes_generate_salt(realm, username), &AesSizes::Aes128));
        Ok(Self {
            keytype: Tag::new(EType::Aes128CtsHmacSha196 as Integer),
            keyvalue: Tag::new(aes_generate_key(password.as_bytes(), &aes_generate_salt(realm, username), &AesSizes::Aes128))
        })
    }

    pub fn new_aes128_hmac_from_aeskey(key: Vec<u8>) -> KerlabResult<Self> {
        Ok(Self {
            keytype: Tag::new(EType::Aes128CtsHmacSha196 as Integer),
            keyvalue: Tag::new(key)
        })
    }

    pub fn new_aes256_hmac(realm: &str, username: &str, password: &str) -> KerlabResult<Self> {
        Ok(Self {
            keytype: Tag::new(EType::Aes256CtsHmacSha196 as Integer),
            keyvalue: Tag::new(aes_generate_key(password.as_bytes(), &aes_generate_salt(realm, username), &AesSizes::Aes256))
        })
    }

    pub fn new_aes256_hmac_from_aeskey(key: Vec<u8>) -> KerlabResult<Self> {
        Ok(Self {
            keytype: Tag::new(EType::Aes256CtsHmacSha196 as Integer),
            keyvalue: Tag::new(key)
        })
    }
}

impl EncryptionKey {
    pub fn encrypt(&self, key_usage: KeyUsage, object: &dyn ASN1) -> KerlabResult<EncryptedData> {
        match EType::try_from(self.keytype.inner)? {
            EType::NoEncryption => {
                Ok(EncryptedData::new(
                    self.keytype.inner,
                    to_der(object)
                ))
            },
            EType::Rc4Hmac => {
                let cipher = Rc4Hmac::new(self.keyvalue.inner.clone(), key_usage).encrypt(&to_der(object));
                Ok(EncryptedData::new(
                    self.keytype.inner,
                    cipher
                ))
            },
            EType::Aes128CtsHmacSha196 => {
                let cipher = Aes::new(self.keyvalue.inner.clone(), key_usage, AesSizes::Aes128).encrypt(&to_der(object))?;
                Ok(EncryptedData::new(
                    self.keytype.inner,
                    cipher
                ))
            },
            EType::Aes256CtsHmacSha196 => {
                let cipher = Aes::new(self.keyvalue.inner.clone(), key_usage, AesSizes::Aes256).encrypt(&to_der(object))?;
                Ok(EncryptedData::new(
                    self.keytype.inner,
                    cipher
                ))
            },
            _ => Err(Error::new(KerlabErrorKind::Crypto, "Unsupported Algorithm"))
        }
    }

    pub fn decrypt<T: ASN1 + Default>(&self, key_usage: KeyUsage, data: &EncryptedData) -> KerlabResult<T> {
        if self.keytype.inner != data.etype.inner {
            return Err(Error::new(KerlabErrorKind::Crypto, "Bad Key"))
        }

        match EType::try_from(self.keytype.inner)? {
            EType::NoEncryption => {
                let mut result = T::default();
                from_ber(&mut result, &data.cipher.inner)?;
                Ok(result)
            },
            EType::Rc4Hmac => {
                let plaintext = Rc4Hmac::new(self.keyvalue.inner.clone(), key_usage).decrypt(&data.cipher.inner)?;
                let mut result = T::default();
                from_ber(&mut result, &plaintext)?;
                Ok(result)
            },
            EType::Aes128CtsHmacSha196 => {
                let plaintext = Aes::new(self.keyvalue.inner.clone(), key_usage, AesSizes::Aes128).decrypt(&data.cipher.inner)?;
                let mut result = T::default();
                from_ber(&mut result, &plaintext)?;
                Ok(result)
            },
            EType::Aes256CtsHmacSha196 => {
                let plaintext = Aes::new(self.keyvalue.inner.clone(), key_usage, AesSizes::Aes256).decrypt(&data.cipher.inner)?;
                let mut result = T::default();
                from_ber(&mut result, &plaintext)?;
                Ok(result)
            },
            _ => Err(Error::new(KerlabErrorKind::Crypto, "Unsupported Algorithm"))
        }
    }
}