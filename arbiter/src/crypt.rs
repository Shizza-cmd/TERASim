use std::ptr;

#[repr(C)]
struct TeraCrypt {
    _private: [u8; 0],
}

extern "C" {
    fn tera_crypt_new(
        client_key1: *const u8,
        client_key2: *const u8,
        server_key1: *const u8,
        server_key2: *const u8,
    ) -> *mut TeraCrypt;
    fn tera_crypt_decrypt(ctx: *mut TeraCrypt, data: *mut u8, len: usize);
    fn tera_crypt_encrypt(ctx: *mut TeraCrypt, data: *mut u8, len: usize);
    fn tera_crypt_free(ctx: *mut TeraCrypt);
}

pub struct Cipher {
    ctx: *mut TeraCrypt,
}

impl Cipher {
    pub fn new(
        client1: &[u8; 128],
        client2: &[u8; 128],
        server1: &[u8; 128],
        server2: &[u8; 128],
    ) -> Self {
        let ctx = unsafe {
            tera_crypt_new(
                client1.as_ptr(),
                client2.as_ptr(),
                server1.as_ptr(),
                server2.as_ptr(),
            )
        };
        assert!(!ctx.is_null(), "tera_crypt_new");
        Self { ctx }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        unsafe { tera_crypt_decrypt(self.ctx, data.as_mut_ptr(), data.len()) }
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        if data.is_empty() {
            return;
        }
        unsafe { tera_crypt_encrypt(self.ctx, data.as_mut_ptr(), data.len()) }
    }
}

impl Drop for Cipher {
    fn drop(&mut self) {
        if !self.ctx.is_null() {
            unsafe { tera_crypt_free(self.ctx) }
            self.ctx = ptr::null_mut();
        }
    }
}

unsafe impl Send for Cipher {}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(seed: u8) -> [u8; 128] {
        let mut out = [0u8; 128];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = seed.wrapping_add(i as u8);
        }
        out
    }

    #[test]
    fn fixed_keys_produce_a_stable_ciphertext() {
        let mut cipher = Cipher::new(&key(1), &key(2), &key(3), &key(4));
        let mut data = *b"TERA-387463-vector!!";
        cipher.encrypt(&mut data);
        assert_eq!(
            data,
            [
                93, 31, 174, 219, 93, 50, 12, 207, 100, 73, 161, 114, 33, 104, 70, 152, 36, 174,
                88, 90,
            ]
        );
    }

    #[test]
    fn the_same_stream_applied_twice_restores_plaintext() {
        let mut first = Cipher::new(&key(9), &key(8), &key(7), &key(6));
        let mut second = Cipher::new(&key(9), &key(8), &key(7), &key(6));
        let mut data = [1u8, 2, 3, 4, 5, 6, 7];
        first.encrypt(&mut data);
        second.encrypt(&mut data);
        assert_eq!(data, [1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn split_chunks_match_one_shot() {
        let mut whole = Cipher::new(&key(9), &key(8), &key(7), &key(6));
        let mut split = Cipher::new(&key(9), &key(8), &key(7), &key(6));
        let mut once = *b"TERA-387463-vector!!";
        let mut parts = once;
        whole.encrypt(&mut once);
        split.encrypt(&mut parts[..3]);
        split.encrypt(&mut parts[3..]);
        assert_eq!(parts, once);
    }
}
