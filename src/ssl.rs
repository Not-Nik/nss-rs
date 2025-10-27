// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::{
    fmt,
    os::raw::{c_uint, c_void},
};
#[cfg(not(feature = "disable-encryption"))]
use std::{os::raw::c_char, ptr::null_mut};

use crate::{
    err::{sec::SEC_ERROR_BAD_DATA, secstatus_to_res, Res},
    nss_prelude::*,
    prio::PRFileDesc,
    Cipher, Epoch, Error, SymKey, Version,
};

mod nss_ssl {
    #![allow(
        dead_code,
        non_upper_case_globals,
        non_snake_case,
        nonstandard_style,
        clippy::all,
        clippy::nursery,
        clippy::pedantic,
        clippy::restriction,
        reason = "For included bindgen code."
    )]
    use crate::{
        err::PRErrorCode,
        nss_prelude::*,
        p11::{CERTCertificateStr, HpkeAeadId, HpkeKdfId, PK11SymKeyStr, SECKEYPrivateKeyStr},
        prio::{PRFileDesc, PRFileInfo, PRFileInfo64, PRIOVec},
        time::PRTime,
    };

    include!(concat!(env!("OUT_DIR"), "/nss_ssl.rs"));
}
pub use nss_ssl::*;

#[expect(non_snake_case, unused, reason = "OK here.")]
mod SSLOption {
    include!(concat!(env!("OUT_DIR"), "/nss_sslopt.rs"));
}

// Remap some constants.
#[expect(non_upper_case_globals, reason = "OK here.")]
pub const SECSuccess: SECStatus = _SECStatus_SECSuccess;
#[expect(non_upper_case_globals, reason = "OK here.")]
pub const SECFailure: SECStatus = _SECStatus_SECFailure;

#[derive(Debug, Copy, Clone)]
#[repr(u32)]
pub enum Opt {
    Locking = SSLOption::SSL_NO_LOCKS,
    Tickets = SSLOption::SSL_ENABLE_SESSION_TICKETS,
    OcspStapling = SSLOption::SSL_ENABLE_OCSP_STAPLING,
    Alpn = SSLOption::SSL_ENABLE_ALPN,
    ExtendedMasterSecret = SSLOption::SSL_ENABLE_EXTENDED_MASTER_SECRET,
    SignedCertificateTimestamps = SSLOption::SSL_ENABLE_SIGNED_CERT_TIMESTAMPS,
    EarlyData = SSLOption::SSL_ENABLE_0RTT_DATA,
    RecordSizeLimit = SSLOption::SSL_RECORD_SIZE_LIMIT,
    Tls13CompatMode = SSLOption::SSL_ENABLE_TLS13_COMPAT_MODE,
    HelloDowngradeCheck = SSLOption::SSL_ENABLE_HELLO_DOWNGRADE_CHECK,
    SuppressEndOfEarlyData = SSLOption::SSL_SUPPRESS_END_OF_EARLY_DATA,
    Grease = SSLOption::SSL_ENABLE_GREASE,
    EnableChExtensionPermutation = SSLOption::SSL_ENABLE_CH_EXTENSION_PERMUTATION,
}

impl Opt {
    #[must_use]
    pub const fn as_int(self) -> PRInt32 {
        self as PRInt32
    }

    // Some options are backwards, like SSL_NO_LOCKS, so use this to manage that.
    fn map_enabled(self, enabled: bool) -> PRIntn {
        let v = match self {
            Self::Locking => !enabled,
            _ => enabled,
        };
        PRIntn::from(v)
    }

    pub(crate) fn set(self, fd: *mut PRFileDesc, value: bool) -> Res<()> {
        secstatus_to_res(unsafe { SSL_OptionSet(fd, self.as_int(), self.map_enabled(value)) })
    }
}

experimental_api!(SSL_HelloRetryRequestCallback(
    fd: *mut PRFileDesc,
    cb: SSLHelloRetryRequestCallback,
    arg: *mut c_void,
));
experimental_api!(SSL_RecordLayerWriteCallback(
    fd: *mut PRFileDesc,
    cb: SSLRecordWriteCallback,
    arg: *mut c_void,
));
experimental_api!(SSL_RecordLayerData(
    fd: *mut PRFileDesc,
    epoch: Epoch,
    ct: SSLContentType::Type,
    data: *const u8,
    len: c_uint,
));
experimental_api!(SSL_SendSessionTicket(
    fd: *mut PRFileDesc,
    extra: *const u8,
    len: c_uint,
));
experimental_api!(SSL_SetMaxEarlyDataSize(fd: *mut PRFileDesc, size: u32));
experimental_api!(SSL_SetResumptionToken(
    fd: *mut PRFileDesc,
    token: *const u8,
    len: c_uint,
));
experimental_api!(SSL_SetResumptionTokenCallback(
    fd: *mut PRFileDesc,
    cb: SSLResumptionTokenCallback,
    arg: *mut c_void,
));

experimental_api!(SSL_GetResumptionTokenInfo(
    token: *const u8,
    token_len: c_uint,
    info: *mut SSLResumptionTokenInfo,
    len: c_uint,
));

experimental_api!(SSL_DestroyResumptionTokenInfo(
    info: *mut SSLResumptionTokenInfo,
));

experimental_api!(SSL_SetCertificateCompressionAlgorithm(
    fd: *mut PRFileDesc,
    t: SSLCertificateCompressionAlgorithm,
));

#[cfg(not(feature = "disable-encryption"))]
experimental_api!(SSL_MakeAead(
    version: PRUint16,
    cipher: PRUint16,
    secret: *mut PK11SymKey,
    label_prefix: *const c_char,
    label_prefix_len: c_uint,
    ctx: *mut *mut SSLAeadContext,
));

#[cfg(not(feature = "disable-encryption"))]
experimental_api!(SSL_AeadEncrypt(
    ctx: *const SSLAeadContext,
    counter: PRUint64,
    aad: *const PRUint8,
    aad_len: c_uint,
    input: *const PRUint8,
    input_len: c_uint,
    output: *const PRUint8,
    output_len: *mut c_uint,
    max_output: c_uint
));

#[cfg(not(feature = "disable-encryption"))]
experimental_api!(SSL_AeadDecrypt(
    ctx: *const SSLAeadContext,
    counter: PRUint64,
    aad: *const PRUint8,
    aad_len: c_uint,
    input: *const PRUint8,
    input_len: c_uint,
    output: *const PRUint8,
    output_len: *mut c_uint,
    max_output: c_uint
));
experimental_api!(SSL_DestroyAead(ctx: *mut SSLAeadContext));
scoped_ptr!(AeadContext, SSLAeadContext, SSL_DestroyAead);

#[cfg(feature = "disable-encryption")]
pub const AEAD_NULL_TAG: &[u8] = &[0x0a; 16];

pub struct Aead {
    #[cfg(not(feature = "disable-encryption"))]
    ctx: AeadContext,
}

#[cfg(not(feature = "disable-encryption"))]
impl Aead {
    unsafe fn from_raw(
        version: Version,
        cipher: Cipher,
        secret: *mut PK11SymKey,
        prefix: &str,
    ) -> Res<Self> {
        let p = prefix.as_bytes();
        let mut ctx: *mut SSLAeadContext = null_mut();
        SSL_MakeAead(
            version,
            cipher,
            secret,
            p.as_ptr().cast(),
            c_uint::try_from(p.len())?,
            &mut ctx,
        )?;
        Ok(Self {
            ctx: AeadContext::from_ptr(ctx)?,
        })
    }

    /// Create a new AEAD instance.
    ///
    /// # Errors
    ///
    /// Returns `Error` when the underlying crypto operations fail.
    pub fn new(version: Version, cipher: Cipher, secret: &SymKey, prefix: &str) -> Res<Self> {
        let s: *mut PK11SymKey = **secret;
        unsafe { Self::from_raw(version, cipher, s, prefix) }
    }

    /// Get the expansion size (authentication tag length) for this AEAD.
    #[must_use]
    #[expect(clippy::missing_const_for_fn, clippy::unused_self)]
    pub fn expansion(&self) -> usize {
        16
    }

    /// Encrypt plaintext with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when encryption fails.
    pub fn encrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        let mut l: c_uint = 0;
        unsafe {
            SSL_AeadEncrypt(
                *self.ctx,
                count,
                aad.as_ptr(),
                c_uint::try_from(aad.len())?,
                input.as_ptr(),
                c_uint::try_from(input.len())?,
                output.as_mut_ptr(),
                &mut l,
                c_uint::try_from(output.len())?,
            )
        }?;
        Ok(&output[..l.try_into()?])
    }

    /// Encrypt plaintext in place with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when encryption fails.
    pub fn encrypt_in_place<'a>(
        &self,
        count: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        if data.len() < self.expansion() {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        let mut l: c_uint = 0;
        unsafe {
            SSL_AeadEncrypt(
                *self.ctx,
                count,
                aad.as_ptr(),
                c_uint::try_from(aad.len())?,
                data.as_ptr(),
                c_uint::try_from(data.len() - self.expansion())?,
                data.as_mut_ptr(),
                &mut l,
                c_uint::try_from(data.len())?,
            )
        }?;
        debug_assert_eq!(usize::try_from(l)?, data.len());
        Ok(data)
    }

    /// Decrypt ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when decryption or authentication fails.
    pub fn decrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        let mut l: c_uint = 0;
        unsafe {
            // Note that NSS insists upon having extra space available for decryption, so
            // the buffer for `output` should be the same length as `input`, even though
            // the final result will be shorter.
            SSL_AeadDecrypt(
                *self.ctx,
                count,
                aad.as_ptr(),
                c_uint::try_from(aad.len())?,
                input.as_ptr(),
                c_uint::try_from(input.len())?,
                output.as_mut_ptr(),
                &mut l,
                c_uint::try_from(output.len())?,
            )
        }?;
        Ok(&output[..l.try_into()?])
    }

    /// Decrypt ciphertext in place with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when decryption or authentication fails.
    pub fn decrypt_in_place<'a>(
        &self,
        count: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        let mut l: c_uint = 0;
        unsafe {
            // Note that NSS insists upon having extra space available for decryption, so
            // the buffer for `output` should be the same length as `input`, even though
            // the final result will be shorter.
            SSL_AeadDecrypt(
                *self.ctx,
                count,
                aad.as_ptr(),
                c_uint::try_from(aad.len())?,
                data.as_ptr(),
                c_uint::try_from(data.len())?,
                data.as_mut_ptr(),
                &mut l,
                c_uint::try_from(data.len())?,
            )
        }?;
        debug_assert_eq!(usize::try_from(l)?, data.len() - self.expansion());
        Ok(&mut data[..l.try_into()?])
    }
}

#[cfg(not(feature = "disable-encryption"))]
impl fmt::Debug for Aead {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[AEAD Context]")
    }
}

#[cfg(feature = "disable-encryption")]
impl Aead {
    fn decrypt_check(&self, _count: u64, _aad: &[u8], input: &[u8]) -> Res<usize> {
        if input.len() < self.expansion() {
            return Err(Error::from(SEC_ERROR_BAD_DATA));
        }

        let len_encrypted = input
            .len()
            .checked_sub(self.expansion())
            .ok_or_else(|| Error::from(SEC_ERROR_BAD_DATA))?;
        // Check that:
        // 1) expansion is all zeros and
        // 2) if the encrypted data is also supplied that at least some values are no zero
        //    (otherwise padding will be interpreted as a valid packet)
        if &input[len_encrypted..] == AEAD_NULL_TAG
            && (len_encrypted == 0 || input[..len_encrypted].iter().any(|x| *x != 0x0))
        {
            Ok(len_encrypted)
        } else {
            Err(Error::from(SEC_ERROR_BAD_DATA))
        }
    }

    /// Create a new AEAD instance.
    ///
    /// # Errors
    ///
    /// Returns `Error` when the underlying crypto operations fail.
    #[expect(clippy::missing_const_for_fn, clippy::unnecessary_wraps)]
    pub fn new(_version: Version, _cipher: Cipher, _secret: &SymKey, _prefix: &str) -> Res<Self> {
        Ok(Self {})
    }

    /// Get the expansion size (authentication tag length) for this AEAD.
    #[must_use]
    #[expect(clippy::missing_const_for_fn, clippy::unused_self)]
    pub fn expansion(&self) -> usize {
        AEAD_NULL_TAG.len()
    }

    /// Encrypt plaintext with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when encryption fails.
    #[expect(clippy::unnecessary_wraps)]
    pub fn encrypt<'a>(
        &self,
        _count: u64,
        _aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        let l = input.len();
        output[..l].copy_from_slice(input);
        output[l..l + self.expansion()].copy_from_slice(AEAD_NULL_TAG);
        Ok(&output[..l + self.expansion()])
    }

    /// Encrypt plaintext in place with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when encryption fails.
    #[expect(clippy::unnecessary_wraps)]
    pub fn encrypt_in_place<'a>(
        &self,
        _count: u64,
        _aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        let pos = data.len() - self.expansion();
        data[pos..].copy_from_slice(AEAD_NULL_TAG);
        Ok(data)
    }

    /// Decrypt ciphertext with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when decryption or authentication fails.
    pub fn decrypt<'a>(
        &self,
        count: u64,
        aad: &[u8],
        input: &[u8],
        output: &'a mut [u8],
    ) -> Res<&'a [u8]> {
        self.decrypt_check(count, aad, input).map(|len| {
            output[..len].copy_from_slice(&input[..len]);
            &output[..len]
        })
    }

    /// Decrypt ciphertext in place with associated data.
    ///
    /// # Errors
    ///
    /// Returns `Error` when decryption or authentication fails.
    pub fn decrypt_in_place<'a>(
        &self,
        count: u64,
        aad: &[u8],
        data: &'a mut [u8],
    ) -> Res<&'a mut [u8]> {
        self.decrypt_check(count, aad, data)
            .map(move |len| &mut data[..len])
    }
}

#[cfg(feature = "disable-encryption")]
impl fmt::Debug for Aead {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[NULL AEAD]")
    }
}

#[cfg(test)]
#[cfg_attr(coverage_nightly, coverage(off))]
mod tests {
    use super::{SSL_GetNumImplementedCiphers, SSL_NumImplementedCiphers};

    #[test]
    fn num_ciphers() {
        assert!(unsafe { SSL_NumImplementedCiphers } > 0);
        assert!(unsafe { SSL_GetNumImplementedCiphers() } > 0);
        assert_eq!(unsafe { SSL_NumImplementedCiphers }, unsafe {
            SSL_GetNumImplementedCiphers()
        });
    }
}
