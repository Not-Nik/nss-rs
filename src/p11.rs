// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(
    dead_code,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    clippy::unwrap_used
)]
use std::{
    cell::RefCell,
    convert::TryFrom as _,
    fmt::{self, Debug, Formatter},
    os::raw::c_uint,
    ptr::null_mut,
};

use pkcs11_bindings::CKA_VALUE;

use crate::{
    err::{secstatus_to_res, Error, Res},
    nss_prelude::SECITEM_FreeItem,
    util::SECItemMut,
};

#[must_use]
pub fn hex_with_len(buf: impl AsRef<[u8]>) -> String {
    use std::fmt::Write as _;
    let buf = buf.as_ref();
    let mut ret = String::with_capacity(10 + buf.len() * 2);
    write!(&mut ret, "[{}]: ", buf.len()).unwrap();
    for b in buf {
        write!(&mut ret, "{b:02x}").unwrap();
    }
    ret
}

#[expect(
    dead_code,
    non_snake_case,
    non_upper_case_globals,
    non_camel_case_types,
    clippy::unreadable_literal,
    reason = "For included bindgen code."
)]
mod nss_p11 {
    #![allow(
        non_snake_case,
        non_upper_case_globals,
        non_camel_case_types,
        clippy::all,
        clippy::nursery,
        clippy::pedantic,
        clippy::restriction,
        reason = "For included bindgen code."
    )]
    use crate::{
        nss_prelude::*,
        prtypes::{PRBool, PRInt32, PRUint32, PRUint8, PRUword},
    };
    include!(concat!(env!("OUT_DIR"), "/nss_p11.rs"));
}

pub use nss_p11::*;

use crate::{null_safe_slice, prtypes::PRBool};

scoped_ptr!(Certificate, CERTCertificate, CERT_DestroyCertificate);
scoped_ptr!(CertList, CERTCertList, CERT_DestroyCertList);

scoped_ptr!(
    SubjectPublicKeyInfo,
    CERTSubjectPublicKeyInfo,
    SECKEY_DestroySubjectPublicKeyInfo
);

scoped_ptr!(PublicKey, SECKEYPublicKey, SECKEY_DestroyPublicKey);
impl_clone!(PublicKey, SECKEY_CopyPublicKey);

impl PublicKey {
    /// Get the HPKE serialization of the public key.
    ///
    /// # Errors
    ///
    /// When the key cannot be exported, which can be because the type is not supported.
    ///
    /// # Panics
    ///
    /// When keys are too large to fit in `c_uint/usize`.  So only on programming error.
    pub fn key_data(&self) -> Res<Vec<u8>> {
        let mut buf = vec![0; 100];
        let mut len: c_uint = 0;
        secstatus_to_res(unsafe {
            PK11_HPKE_Serialize(
                **self,
                buf.as_mut_ptr(),
                &mut len,
                c_uint::try_from(buf.len())?,
            )
        })?;
        buf.truncate(usize::try_from(len)?);
        Ok(buf)
    }
}

impl Debug for PublicKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "PublicKey {}", hex_with_len(b))
        } else {
            write!(f, "Opaque PublicKey")
        }
    }
}

scoped_ptr!(PrivateKey, SECKEYPrivateKey, SECKEY_DestroyPrivateKey);
impl_clone!(PrivateKey, SECKEY_CopyPrivateKey);

impl PrivateKey {
    /// Get the bits of the private key.
    ///
    /// # Errors
    ///
    /// When the key cannot be exported, which can be because the type is not supported
    /// or because the key data cannot be extracted from the PKCS#11 module.
    ///
    /// # Panics
    ///
    /// When the values are too large to fit.  So never.
    pub fn key_data(&self) -> Res<Vec<u8>> {
        let mut key_item = SECItemMut::make_empty();
        secstatus_to_res(unsafe {
            PK11_ReadRawAttribute(
                PK11ObjectType::PK11_TypePrivKey,
                (**self).cast(),
                CKA_VALUE,
                key_item.as_mut(),
            )
        })?;
        let slc = unsafe { null_safe_slice(key_item.as_ref().data, key_item.as_ref().len) };
        let key = Vec::from(slc);
        // The data that `key_item` refers to needs to be freed, but we can't
        // use the scoped `Item` implementation.  This is OK as long as nothing
        // panics between `PK11_ReadRawAttribute` succeeding and here.
        unsafe {
            SECITEM_FreeItem(key_item.as_mut(), PRBool::from(false));
        }
        Ok(key)
    }
}
unsafe impl Send for PrivateKey {}

impl Debug for PrivateKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "PrivateKey {}", hex_with_len(b))
        } else {
            write!(f, "Opaque PrivateKey")
        }
    }
}

scoped_ptr!(Slot, PK11SlotInfo, PK11_FreeSlot);

impl Slot {
    pub fn internal() -> Res<Self> {
        unsafe { Self::from_ptr(PK11_GetInternalSlot()) }
    }
}

// Note: PK11SymKey is internally reference counted
scoped_ptr!(SymKey, PK11SymKey, PK11_FreeSymKey);
impl_clone!(SymKey, PK11_ReferenceSymKey);

impl SymKey {
    /// You really don't want to use this.
    ///
    /// # Errors
    ///
    /// Internal errors in case of failures in NSS.
    pub fn as_bytes(&self) -> Res<&[u8]> {
        secstatus_to_res(unsafe { PK11_ExtractKeyValue(**self) })?;

        let key_item = unsafe { PK11_GetKeyData(**self) };
        // This is accessing a value attached to the key, so we can treat this as a borrow.
        match unsafe { key_item.as_mut() } {
            None => Err(Error::InternalError),
            Some(key) => Ok(unsafe { null_safe_slice(key.data, key.len) }),
        }
    }
}

impl Debug for SymKey {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        if let Ok(b) = self.as_bytes() {
            write!(f, "SymKey {}", hex_with_len(b))
        } else {
            write!(f, "Opaque SymKey")
        }
    }
}

impl Default for SymKey {
    fn default() -> Self {
        Self { ptr: null_mut() }
    }
}

unsafe fn destroy_pk11_context(ctxt: *mut PK11Context) {
    PK11_DestroyContext(ctxt, PRBool::from(true));
}
scoped_ptr!(Context, PK11Context, destroy_pk11_context);

#[cfg(feature = "disable-random")]
thread_local! {
    static CURRENT_VALUE: std::cell::Cell<u8> = const { std::cell::Cell::new(0) };
}

#[cfg(feature = "disable-random")]
/// Fill a buffer with a predictable sequence of bytes.
pub fn randomize<B: AsMut<[u8]>>(mut buf: B) -> B {
    let m_buf = buf.as_mut();
    for v in m_buf.iter_mut() {
        *v = CURRENT_VALUE.get();
        CURRENT_VALUE.set(v.wrapping_add(1));
    }
    buf
}

/// Fill a buffer with randomness.
///
/// # Panics
///
/// When `size` is too large or NSS fails.
#[cfg(not(feature = "disable-random"))]
pub fn randomize<B: AsMut<[u8]>>(mut buf: B) -> B {
    let m_buf = buf.as_mut();
    let len = std::os::raw::c_int::try_from(m_buf.len()).expect("usize fits into c_int");
    secstatus_to_res(unsafe { PK11_GenerateRandom(m_buf.as_mut_ptr(), len) }).expect("NSS failed");
    buf
}

struct RandomCache {
    cache: [u8; Self::SIZE],
    used: usize,
}

impl RandomCache {
    const SIZE: usize = 256;
    const CUTOFF: usize = 32;

    const fn new() -> Self {
        Self {
            cache: [0; Self::SIZE],
            used: Self::SIZE,
        }
    }

    fn randomize<B: AsMut<[u8]>>(&mut self, mut buf: B) -> B {
        let m_buf = buf.as_mut();
        debug_assert!(m_buf.len() <= Self::CUTOFF);
        let avail = Self::SIZE - self.used;
        if m_buf.len() <= avail {
            m_buf.copy_from_slice(&self.cache[self.used..self.used + m_buf.len()]);
            self.used += m_buf.len();
        } else {
            if avail > 0 {
                m_buf[..avail].copy_from_slice(&self.cache[self.used..]);
            }
            randomize(&mut self.cache[..]);
            self.used = m_buf.len() - avail;
            m_buf[avail..].copy_from_slice(&self.cache[..self.used]);
        }
        buf
    }
}

/// Generate a randomized array.
///
/// # Panics
///
/// When `size` is too large or NSS fails.
#[must_use]
pub fn random<const N: usize>() -> [u8; N] {
    thread_local!(static CACHE: RefCell<RandomCache> = const { RefCell::new(RandomCache::new()) });

    let buf = [0; N];
    if N <= RandomCache::CUTOFF {
        CACHE.with_borrow_mut(|c| c.randomize(buf))
    } else {
        randomize(buf)
    }
}

impl_into_result!(SECOidData);

#[cfg(test)]
mod test {
    use test_fixture::fixture_init;

    use super::RandomCache;
    use crate::random;

    #[cfg(not(feature = "disable-random"))]
    #[test]
    fn randomness() {
        use crate::randomize;

        fixture_init();
        // If any of these ever fail, there is either a bug, or it's time to buy a lottery ticket.
        assert_ne!(random::<16>(), randomize([0; 16]));
        assert_ne!([0; 16], random::<16>());
        assert_ne!([0; 64], random::<64>());
    }

    #[test]
    fn cache_random_lengths() {
        const ZERO: [u8; 256] = [0; 256];

        fixture_init();
        let mut cache = RandomCache::new();
        let mut buf = [0; 256];
        let bits = usize::BITS - (RandomCache::CUTOFF - 1).leading_zeros();
        let mask = 0xff >> (u8::BITS - bits);

        for _ in 0..100 {
            let len = loop {
                let len = usize::from(random::<1>()[0] & mask) + 1;
                if len <= RandomCache::CUTOFF {
                    break len;
                }
            };
            buf.fill(0);
            if len >= 16 {
                assert_ne!(&cache.randomize(&mut buf[..len])[..len], &ZERO[..len]);
            }
        }
    }
}
