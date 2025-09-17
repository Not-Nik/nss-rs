// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

#![allow(dead_code)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use crate::err::{secstatus_to_res, Error, Res};
use crate::util::SECItemMut;

use std::convert::TryFrom;
use std::ops::{Deref, DerefMut};
use std::os::raw::{c_int, c_uint};

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

#[allow(clippy::upper_case_acronyms)]
#[allow(clippy::unreadable_literal)]
#[allow(unknown_lints, clippy::borrow_as_ptr)]
mod nss_p11 {
    use crate::nss_prelude::*;
    use crate::prtypes::*;
    include!(concat!(env!("OUT_DIR"), "/nss_p11.rs"));
}

use crate::prtypes::*;
pub use nss_p11::*;

macro_rules! scoped_ptr {
    ($scoped:ident, $target:ty, $dtor:path) => {
        pub struct $scoped {
            ptr: *mut $target,
        }

        impl $scoped {
            /// Create a new instance of `$scoped` from a pointer.
            ///
            /// # Errors
            /// When passed a null pointer generates an error.
            pub fn from_ptr(ptr: *mut $target) -> Result<Self, crate::err::Error> {
                if ptr.is_null() {
                    Err(crate::err::Error::last_nss_error())
                } else {
                    Ok(Self { ptr })
                }
            }
        }

        impl Deref for $scoped {
            type Target = *mut $target;

            fn deref(&self) -> &*mut $target {
                &self.ptr
            }
        }

        impl DerefMut for $scoped {
            fn deref_mut(&mut self) -> &mut *mut $target {
                &mut self.ptr
            }
        }

        impl Drop for $scoped {
            #[allow(unused_must_use)]
            fn drop(&mut self) {
                unsafe { $dtor(self.ptr) };
            }
        }
    };
}

scoped_ptr!(Certificate, CERTCertificate, CERT_DestroyCertificate);
scoped_ptr!(CertList, CERTCertList, CERT_DestroyCertList);
scoped_ptr!(PublicKey, SECKEYPublicKey, SECKEY_DestroyPublicKey);

impl PublicKey {
    /// Get the HPKE serialization of the public key.
    ///
    /// # Errors
    /// When the key cannot be exported, which can be because the type is not supported.
    /// # Panics
    /// When keys are too large to fit in `c_uint/usize`.  So only on programming error.
    pub fn key_data(&self) -> Res<Vec<u8>> {
        let mut buf = vec![0; 100];
        let mut len: c_uint = 0;
        secstatus_to_res(unsafe {
            PK11_HPKE_Serialize(
                **self,
                buf.as_mut_ptr(),
                &mut len,
                c_uint::try_from(buf.len()).unwrap(),
            )
        })?;
        buf.truncate(usize::try_from(len).unwrap());
        Ok(buf)
    }
}

impl Clone for PublicKey {
    fn clone(&self) -> Self {
        let ptr = unsafe { SECKEY_CopyPublicKey(self.ptr) };
        assert!(!ptr.is_null());
        Self { ptr }
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(b) = self.key_data() {
            write!(f, "PublicKey {}", hex_with_len(b))
        } else {
            write!(f, "Opaque PublicKey")
        }
    }
}

scoped_ptr!(PrivateKey, SECKEYPrivateKey, SECKEY_DestroyPrivateKey);

impl PrivateKey {
    /// Get the bits of the private key.
    ///
    /// # Errors
    /// When the key cannot be exported, which can be because the type is not supported
    /// or because the key data cannot be extracted from the PKCS#11 module.
    /// # Panics
    /// When the values are too large to fit.  So never.
    pub fn key_data(&self) -> Res<Vec<u8>> {
        let mut key_item = SECItemMut::make_empty();
        secstatus_to_res(unsafe {
            PK11_ReadRawAttribute(
                PK11ObjectType::PK11_TypePrivKey,
                (**self).cast(),
                CK_ATTRIBUTE_TYPE::from(CKA_VALUE),
                key_item.as_mut(),
            )
        })?;
        Ok(key_item.as_slice().to_owned())
    }
}
unsafe impl Send for PrivateKey {}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        let ptr = unsafe { SECKEY_CopyPrivateKey(self.ptr) };
        assert!(!ptr.is_null());
        Self { ptr }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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
        let p = unsafe { PK11_GetInternalSlot() };
        Slot::from_ptr(p)
    }
}

scoped_ptr!(SymKey, PK11SymKey, PK11_FreeSymKey);

impl SymKey {
    /// You really don't want to use this.
    ///
    /// # Errors
    /// Internal errors in case of failures in NSS.
    pub fn as_bytes(&self) -> Res<&[u8]> {
        secstatus_to_res(unsafe { PK11_ExtractKeyValue(**self) })?;

        let key_item = unsafe { PK11_GetKeyData(**self) };
        // This is accessing a value attached to the key, so we can treat this as a borrow.
        match unsafe { key_item.as_mut() } {
            None => Err(Error::InternalError),
            Some(key) => Ok(unsafe { std::slice::from_raw_parts(key.data, key.len as usize) }),
        }
    }
}

impl Clone for SymKey {
    fn clone(&self) -> Self {
        let ptr = unsafe { PK11_ReferenceSymKey(self.ptr) };
        assert!(!ptr.is_null());
        Self { ptr }
    }
}

impl std::fmt::Debug for SymKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if let Ok(b) = self.as_bytes() {
            write!(f, "SymKey {}", hex_with_len(b))
        } else {
            write!(f, "Opaque SymKey")
        }
    }
}

unsafe fn destroy_pk11_context(ctxt: *mut PK11Context) {
    PK11_DestroyContext(ctxt, PRBool::from(true));
}
scoped_ptr!(Context, PK11Context, destroy_pk11_context);

/// Generate a randomized buffer.
/// # Panics
/// When `size` is too large or NSS fails.
#[must_use]
pub fn random(size: usize) -> Vec<u8> {
    let mut buf = vec![0; size];
    secstatus_to_res(unsafe {
        PK11_GenerateRandom(buf.as_mut_ptr(), c_int::try_from(buf.len()).unwrap())
    })
    .unwrap();
    buf
}

#[cfg(test)]
mod test {
    use super::random;
    use test_fixture::fixture_init;

    #[test]
    fn randomness() {
        fixture_init();
        // If this ever fails, there is either a bug, or it's time to buy a lottery ticket.
        assert_ne!(random(16), random(16));
    }
}
