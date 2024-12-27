use scrypt::password_hash::rand_core::{OsRng, RngCore};

pub fn rand_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![];
    bytes.resize(len, 0);
    OsRng.fill_bytes(bytes.as_mut_slice());
    bytes
}

#[cfg(test)]
mod tests {
    use super::rand_bytes;

    #[test]
    fn test_rand() {
        let mut zero_bytes = vec![];
        zero_bytes.resize(100, 0_u8);
        let bytes1 = rand_bytes(100);
        let bytes2 = rand_bytes(100);
        assert_ne!(bytes1, bytes2);
        assert_ne!(bytes1, zero_bytes);
        assert_ne!(bytes2, zero_bytes);
    }
}