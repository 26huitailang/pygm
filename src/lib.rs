use std::str;

use hex::{encode, FromHex, FromHexError};
use libsm::sm4::cipher_mode::Sm4CipherMode;
use libsm::sm4::error::{Sm4Error, Sm4Result};
use libsm::sm4::Mode;
use pyo3::{exceptions::PyValueError, prelude::*};
use pyo3::exceptions::PyUnicodeDecodeError;

// use rand::RngCore;

// #[warn(dead_code)]
// fn rand_block() -> [u8; 16] {
//     let mut rng = rand::thread_rng();
//     let mut block: [u8; 16] = [0; 16];
//     rng.fill_bytes(&mut block[..]);
//     block
// }

struct Sm4Cbc {
    cipher: Sm4CipherMode,
}

impl Sm4Cbc {
    fn new(key: &[u8]) -> Self {
        match Sm4CipherMode::new(key, Mode::Cbc) {
            Ok(sm4_cipher_mode) => {
                println!("Sm4CiperMode object created successfully!");
                Self { cipher: sm4_cipher_mode }
            }
            Err(err) => {
                eprintln!("Error creating Sm4CipherMode object: {}", err);
                panic!("Error creating Sm4CipherMode object: {}", err);
            }
        }
    }

    fn encrypt(&self, plaintext: &str, iv: &[u8]) -> Sm4Result<Vec<u8>> {
        // let iv = rand_block();
        self.cipher.encrypt(&[], plaintext.as_bytes(), &iv)
    }

    fn decrypt(
        &self,
        ciphertext: &[u8],
        iv: &[u8],
    ) -> Sm4Result<Vec<u8>> {
        self.cipher.decrypt(&[], ciphertext, &iv)
    }
}

#[pyfunction]
fn sm4_cbc_encrypt(key_hex: String, plaintext: String, iv_hex: String) -> PyResult<String> {
    let key_bytes = Vec::from_hex(&key_hex).map_err(|err| MyFromHexError(err))?;
    let iv_bytes = Vec::from_hex(&iv_hex).map_err(|err| MyFromHexError(err))?;

    let sm4_cbc = Sm4Cbc::new(&key_bytes);
    let ciphertext = sm4_cbc.encrypt(&plaintext, &iv_bytes).map_err(|err| MySm4Error(err))?;

    // let result_string = String::from_utf8(ciphertext)
    //     .map_err(|err| PyUnicodeDecodeError::new_err(format!("Invalid UTF-8 sequence: {}", err)))?;
    let result_string = encode(ciphertext);
    Ok(result_string)
}

struct MyFromHexError(FromHexError);

impl From<MyFromHexError> for PyErr {
    fn from(err: MyFromHexError) -> Self {
        match err.0 {
            FromHexError::InvalidHexCharacter { c, index } => {
                PyValueError::new_err(format!("Invalid hex character '{}' at index {}", c, index))
            }
            FromHexError::OddLength => PyValueError::new_err("Odd length hex string"),
            FromHexError::InvalidStringLength => PyValueError::new_err("Invalid string length"),
        }
    }
}

struct MySm4Error(Sm4Error);

impl From<MySm4Error> for PyErr {
    fn from(error: MySm4Error) -> Self {
        match error.0 {
            Sm4Error::ErrorBlockSize => PyValueError::new_err("SM4: Incorrect block size"),
            Sm4Error::ErrorDataLen => PyValueError::new_err("SM4: Invalid data length"),
            Sm4Error::InvalidLastU8 => PyValueError::new_err("SM4: Invalid last byte"),
            Sm4Error::InvalidTag => PyValueError::new_err("SM4: Invalid authentication tag"),
        }
    }
}

#[pyfunction]
fn sm4_cbc_decrypt(key_hex: String, ciphertext: String, iv_hex: String) -> PyResult<String> {
    let key_bytes = Vec::from_hex(&key_hex).map_err(|err| MyFromHexError(err))?;
    let ciphertext_bytes = Vec::from_hex(&ciphertext).map_err(|err| MyFromHexError(err))?;
    let iv_bytes = Vec::from_hex(&iv_hex).map_err(|err| MyFromHexError(err))?;

    let sm4_cbc = Sm4Cbc::new(&key_bytes);
    let plaintext = sm4_cbc.decrypt(&ciphertext_bytes, &iv_bytes).map_err(|err| MySm4Error(err))?;

    let plaintext_str = String::from_utf8(plaintext).map_err(|err| PyUnicodeDecodeError::new_err(format!("Invalid UTF-8 sequence: {}", err)))?;
    Ok(plaintext_str)
}

#[pymodule]
fn pygm(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(sm4_cbc_encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(sm4_cbc_decrypt, m)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_HEX: &str = "0123456789ABCDEF0123456789ABCDEF";
    const IV_HEX: &str = "00000000000000000000000000000000";

    #[test]
    fn test_sm4_cbc_encrypt_and_decrypt() {
        // for loop test, loop plaintext list
        let plaintext_list = vec![
            "0123456789ABCDEF0123456789ABCDEF",
            "FEDCBA9876543210FEDCBA9876543210",
            "ABCDEF0123456789ABCDEF0123456789",
            "0123456789ABCDEF0123456789ABCDEF",
            "FEDCBA9876543210FEDCBA9876543210",
            "ABCDEF0123456789ABCDEF0123456789",
            "1qaz2wsx#EDC",
        ];

        for plaintext in plaintext_list {
            // 对明文进行加密
            let encrypted_hex = sm4_cbc_encrypt(KEY_HEX.to_owned(), plaintext.to_owned(), IV_HEX.to_owned())
                .expect("Encryption failed");
            // 对加密后的密文进行解密
            let decrypted_hex = sm4_cbc_decrypt(KEY_HEX.to_owned(), encrypted_hex, IV_HEX.to_owned())
                .expect("Decryption failed");

            println!("{} {}", decrypted_hex, plaintext);
            assert_eq!(decrypted_hex, plaintext);
        }
    }
}
