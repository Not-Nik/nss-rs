// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ptr;

use pkcs11_bindings::{
    CKF_DERIVE, CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_KEY_PAIR_GEN, CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
};

// use crate::p11::SECKEY_CreateSubjectPublicKeyInfo;
use crate::Error;
use crate::{
    der,
    err::IntoResult,
    init,
    p11::{
        PK11_ExportDERPrivateKeyInfo, PK11_GenerateKeyPairWithOpFlags,
        PK11_ImportDERPrivateKeyInfoAndReturnKey, Slot, KU_ALL, PK11_ATTR_EXTRACTABLE,
        PK11_ATTR_INSENSITIVE, PK11_ATTR_SESSION,
    },
    PrivateKey, PublicKey, SECItem, SECItemBorrowed,
};

//
// Constants
//

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EcCurve {
    P256,
    P384,
    P521,
    X25519,
    Ed25519,
}

pub type EcdhPublicKey = PublicKey;
pub type EcdhPrivateKey = PrivateKey;

pub struct EcdhKeypair {
    pub public: EcdhPublicKey,
    pub private: EcdhPrivateKey,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ecdh(EcCurve);

impl Ecdh {
    #[must_use]
    pub const fn new(curve: EcCurve) -> Self {
        Self(curve)
    }

    pub fn generate_keypair(curve: &EcCurve) -> Result<EcdhKeypair, Error> {
        ecdh_keygen(curve)
    }
}

// Object identifiers in DER tag-length-value form
pub const OID_EC_PUBLIC_KEY_BYTES: &[u8] = &[
    /* RFC 5480 (id-ecPublicKey) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
];
pub const OID_SECP256R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp256r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
];
pub const OID_SECP384R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp384r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x34,
];
pub const OID_SECP521R1_BYTES: &[u8] = &[
    /* RFC 5480 (secp521r1) */
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x35,
];

pub const OID_ED25519_BYTES: &[u8] = &[/* RFC 8410 (id-ed25519) */ 0x2b, 0x65, 0x70];
pub const OID_RS256_BYTES: &[u8] = &[
    /* RFC 4055 (sha256WithRSAEncryption) */
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
];

pub const OID_X25519_BYTES: &[u8] = &[
    /* https://tools.ietf.org/html/draft-josefsson-pkix-newcurves-01
     * 1.3.6.1.4.1.11591.15.1 */
    0x2b, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01,
];

pub fn object_id(val: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::with_capacity(der::MAX_TAG_AND_LENGTH_BYTES + val.len());
    der::write_tag_and_length(&mut out, der::TAG_OBJECT_ID, val.len())?;
    out.extend_from_slice(val);
    Ok(out)
}

fn ec_curve_to_oid(alg: &EcCurve) -> Vec<u8> {
    match alg {
        EcCurve::X25519 => OID_X25519_BYTES.to_vec(),
        EcCurve::Ed25519 => OID_ED25519_BYTES.to_vec(),
        EcCurve::P256 => OID_SECP256R1_BYTES.to_vec(),
        EcCurve::P384 => OID_SECP384R1_BYTES.to_vec(),
        EcCurve::P521 => OID_SECP521R1_BYTES.to_vec(),
    }
}

const fn ec_curve_to_ckm(alg: &EcCurve) -> pkcs11_bindings::CK_MECHANISM_TYPE {
    match alg {
        EcCurve::P256 | EcCurve::P384 | EcCurve::P521 => CKM_EC_KEY_PAIR_GEN,
        EcCurve::Ed25519 => CKM_EC_EDWARDS_KEY_PAIR_GEN,
        EcCurve::X25519 => CKM_EC_MONTGOMERY_KEY_PAIR_GEN,
    }
}

//
// Curve functions
//

pub fn ecdh_keygen(curve: &EcCurve) -> Result<EcdhKeypair, Error> {
    init()?;

    // Get the OID for the Curve
    let curve_oid = ec_curve_to_oid(curve);
    let oid_bytes = object_id(&curve_oid)?;
    let mut oid = SECItemBorrowed::wrap(&oid_bytes)?;
    let oid_ptr: *mut SECItem = oid.as_mut();

    // Get the Mechanism based on the Curve and its use
    let ckm = ec_curve_to_ckm(curve);

    // Get the PKCS11 slot
    let slot = Slot::internal()?;

    // Create a pointer for the public key
    let mut pk_ptr = ptr::null_mut();

    // https://github.com/mozilla/nss-gk-api/issues/1
    unsafe {
        let sk =
            // Type of `param` argument depends on mechanism. For EC keygen it is
            // `SECKEYECParams *` which is a typedef for `SECItem *`.
            PK11_GenerateKeyPairWithOpFlags(
                *slot,
                ckm,
                oid_ptr.cast(),
                &mut pk_ptr,
                PK11_ATTR_EXTRACTABLE | PK11_ATTR_INSENSITIVE | PK11_ATTR_SESSION,
                CKF_DERIVE,
                CKF_DERIVE,
                ptr::null_mut(),
            )
            .into_result()?;

        let pk = EcdhPublicKey::from_ptr(pk_ptr)?;

        let kp = EcdhKeypair {
            public: pk,
            private: sk,
        };

        Ok(kp)
    }
}

pub fn export_ec_private_key_pkcs8(key: &PrivateKey) -> Result<Vec<u8>, Error> {
    init()?;
    unsafe {
        let sk: crate::ScopedSECItem =
            PK11_ExportDERPrivateKeyInfo(**key, ptr::null_mut()).into_result()?;
        return Ok(sk.into_vec());
    }
}

pub fn import_ec_private_key_pkcs8(pki: &[u8]) -> Result<PrivateKey, Error> {
    init()?;

    // Get the PKCS11 slot
    let slot = Slot::internal()?;
    let mut der_pki = SECItemBorrowed::wrap(pki)?;
    let der_pki_ptr: *mut SECItem = der_pki.as_mut();

    // Create a pointer for the private key
    let mut pk_ptr = ptr::null_mut();

    unsafe {
        let r = PK11_ImportDERPrivateKeyInfoAndReturnKey(
            *slot,
            der_pki_ptr,
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
            KU_ALL,
            &mut pk_ptr,
            ptr::null_mut(),
        );
        let sk = EcdhPrivateKey::from_ptr(pk_ptr)?;
        match r {
            0 => Ok(sk),
            _ => Err(Error::InvalidInput),
        }
    }
}

// // I think it should be like this:
// pub fn export_ec_public_key_spki(key: PublicKey)
// {
//     unsafe{

//     let a = SECKEY_CreateSubjectPublicKeyInfo(*key);
//     // let template = CERT_SubjectPublicKeyInfoTemplate;
//     // let encoded = SEC_ASN1EncodeItem();

//     }

// }
