// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use std::ptr;

use pkcs11_bindings::{CKF_DERIVE, CKM_EC_KEY_PAIR_GEN};

use crate::{
    der,
    err::IntoResult,
    init,
    p11::{
        PK11_GenerateKeyPairWithOpFlags, PrivateKey, PublicKey, Slot, PK11_ATTR_EXTRACTABLE,
        PK11_ATTR_INSENSITIVE, PK11_ATTR_SESSION,
    },
    Error, SECItem, SECItemBorrowed,
};

//
// Constants
//

pub enum EcCurve {
    CurveP256,
    CurveP384,
    CurveP521,
    Curve25519,
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
pub const OID_ED25519_BYTES: &[u8] = &[/* RFC 8410 (id-ed25519) */ 0x2b, 0x65, 0x70];
pub const OID_RS256_BYTES: &[u8] = &[
    /* RFC 4055 (sha256WithRSAEncryption) */
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
];

// fn ec_curve_to_ckm(alg: &EcCurve) -> p11::CK_MECHANISM_TYPE {
//     match alg {
//         EcCurve::CurveP256 => p11::CKM_EC_KEY_PAIR_GEN.into(),
//         &EcCurve::CurveP384 | &EcCurve::CurveP521 | &EcCurve::Curve25519 => todo!(),
//     }
// }

pub fn object_id(val: &[u8]) -> Result<Vec<u8>, crate::Error> {
    let mut out = Vec::with_capacity(der::MAX_TAG_AND_LENGTH_BYTES + val.len());
    der::write_tag_and_length(&mut out, der::TAG_OBJECT_ID, val.len())?;
    out.extend_from_slice(val);
    Ok(out)
}

fn ec_curve_to_oid(alg: &EcCurve) -> Result<Vec<u8>, Error> {
    match alg {
        EcCurve::CurveP256 => Ok(OID_SECP256R1_BYTES.to_vec()),
        _ => Err(Error::UnsupportedCurve),
    }
}

//
// Curve function
//

pub fn keygen(alg: EcCurve) -> Result<(PrivateKey, PublicKey), crate::Error> {
    init()?;

    // Get the OID for the Curve
    let curve_oid = ec_curve_to_oid(&alg)?;
    let oid_bytes = object_id(&curve_oid)?;
    let mut oid = SECItemBorrowed::wrap(&oid_bytes)?;
    let oid_ptr: *mut SECItem = oid.as_mut();

    let slot = Slot::internal()?;

    let mut client_public_ptr = ptr::null_mut();

    // https://github.com/mozilla/nss-gk-api/issues/1
    unsafe {
        let client_private =
            // Type of `param` argument depends on mechanism. For EC keygen it is
            // `SECKEYECParams *` which is a typedef for `SECItem *`.
            PK11_GenerateKeyPairWithOpFlags(
                *slot,
                CKM_EC_KEY_PAIR_GEN,
                oid_ptr.cast(),
                &mut client_public_ptr,
                PK11_ATTR_EXTRACTABLE | PK11_ATTR_INSENSITIVE | PK11_ATTR_SESSION,
                CKF_DERIVE,
                CKF_DERIVE,
                ptr::null_mut(),
            )
            .into_result()?;

        let client_public = PublicKey::from_ptr(client_public_ptr)?;

        Ok((client_private, client_public))
    }
}
