//! Sign a file into a Baseline LT ASiC-E container with an Estonian demo ID card.
//!
//! ```sh
//! cargo run --features pkcs11 --example sign_id_card -- \
//!     test.txt test.asice testESTEID2025.crt
//! ```

use allkiri::{pkcs11, sign_container, SigningConfig};
use x509_cert::der::{Decode, Encode};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, output, ca_path] = args.as_slice() else {
        eprintln!("usage: sign_id_card <file> <out.asice> <issuing-ca.pem>");
        std::process::exit(2);
    };

    let card = pkcs11::IdCard::find()?;
    println!("Signing with ID card {}", card.document_number());
    let pin2 = rpassword::prompt_password("PIN2: ")?;
    let signer = pkcs11::id_card_signer_for(&card, &pin2)?;

    let mut config = SigningConfig::demo();
    let ca_bytes = std::fs::read(ca_path)?;
    config.issuer_certs_der = if ca_bytes.starts_with(b"-----") {
        x509_cert::Certificate::load_pem_chain(&ca_bytes)?
            .iter()
            .map(|c| c.to_der())
            .collect::<Result<Vec<_>, _>>()?
    } else {
        x509_cert::Certificate::from_der(&ca_bytes)?;
        vec![ca_bytes]
    };

    let name = input.rsplit('/').next().unwrap();
    let mime = match input.rsplit_once('.').map(|(_, ext)| ext) {
        Some("pdf") => "application/pdf",
        Some("txt") => "text/plain",
        _ => "application/octet-stream",
    };

    let mut container = asic_e::Container::new();
    container.add_file(name, mime, std::fs::read(input)?)?;
    let doc = sign_container(&mut container, &signer, &config)?;
    container.save(output)?;
    println!("wrote {output} ({doc})");
    Ok(())
}
