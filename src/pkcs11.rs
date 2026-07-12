//! Signing with a PKCS#11 token, including the Estonian ID card.

pub use esteid_cryptoki::{EstEidError, IdCard};
pub use xades_pkcs11::{Pkcs11Options, Pkcs11Signer, SlotSelector};

use crate::Result;

/// Open the signing key (PIN2) of the sole connected Estonian ID card.
///
/// The returned signer produces qualified signatures: pass it to
/// [`crate::sign_container`].
pub fn id_card_signer(pin2: &str) -> Result<Pkcs11Signer> {
    let card = IdCard::find()?;
    id_card_signer_for(&card, pin2)
}

/// Open the signing key (PIN2) of a specific card from [`IdCard::list`].
pub fn id_card_signer_for(card: &IdCard, pin2: &str) -> Result<Pkcs11Signer> {
    let key = card.open_signing(pin2)?;
    Ok(Pkcs11Signer::from_token_key(
        key,
        Some(card.signing_certificate_der().to_vec()),
    )?)
}
