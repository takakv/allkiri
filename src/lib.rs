pub use asic_e;
pub use xades;

#[cfg(all(feature = "pkcs11", not(target_arch = "wasm32")))]
pub mod pkcs11;

use xades::DataObject;

/// SK ID Solutions production timestamping service (requires a contract).
pub const PRODUCTION_TSA_URL: &str = "http://tsa.sk.ee";
/// SK ID Solutions demo timestamping service.
pub const DEMO_TSA_URL: &str = "http://tsa.demo.sk.ee/tsa";

/// Errors from either layer.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Container (zip layout, manifest) error.
    #[error(transparent)]
    Container(#[from] asic_e::LibError),
    /// Signature creation or validation error.
    #[error(transparent)]
    Signature(#[from] xades::LibError),
    /// ID card discovery or PKCS#11 error.
    #[cfg(all(feature = "pkcs11", not(target_arch = "wasm32")))]
    #[error(transparent)]
    IdCard(#[from] esteid_cryptoki::EstEidError),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Signature level to produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureLevel {
    /// Baseline B: cryptographic signature only.
    B,
    /// Baseline LT: B + signature timestamp + OCSP proof.
    Lt,
}

#[derive(Debug, Clone)]
pub struct SigningConfig {
    pub level: SignatureLevel,
    /// RFC 3161 timestamping service used for LT signatures.
    pub tsa_url: String,
    /// DER certificates completing the signer's chain.
    /// At least the issuing CA is required for LT.
    pub issuer_certs_der: Vec<Vec<u8>>,
    /// Underlying XAdES options (e.g. claimed signing time).
    pub options: xades::SigningOptions,
}

impl SigningConfig {
    /// LT signing against SK's production services.
    pub fn production() -> Self {
        Self {
            level: SignatureLevel::Lt,
            tsa_url: PRODUCTION_TSA_URL.into(),
            issuer_certs_der: Vec::new(),
            options: xades::SigningOptions::default(),
        }
    }

    /// LT signing against SK's demo services.
    pub fn demo() -> Self {
        Self {
            tsa_url: DEMO_TSA_URL.into(),
            ..Self::production()
        }
    }

    /// B-level signing: no timestamp or OCSP.
    pub fn b_level() -> Self {
        Self {
            level: SignatureLevel::B,
            ..Self::production()
        }
    }
}

impl Default for SigningConfig {
    fn default() -> Self {
        Self::production()
    }
}

/// Sign all data files in the container and append the signature document.
///
/// Returns the entry name of the added signature document
/// (e.g. `META-INF/signatures0.xml`).
pub fn sign_container(
    container: &mut asic_e::Container,
    signer: &dyn xades::Signer,
    config: &SigningConfig,
) -> Result<String> {
    let signature = {
        let files = data_objects(container);
        let created = xades::sign(&files, signer, &config.options)?;
        match config.level {
            SignatureLevel::B => created,
            #[cfg(feature = "network")]
            SignatureLevel::Lt => created.extend_to_lt(&xades::LtConfig {
                tsa_url: config.tsa_url.clone(),
                issuer_certs_der: config.issuer_certs_der.clone(),
            })?,
            #[cfg(not(feature = "network"))]
            SignatureLevel::Lt => {
                return Err(Error::Signature(xades::LibError::Unsupported(
                    "LT signing needs the `network` feature (or use \
                     xades::CreatedSignature::extend_to_lt_with directly)"
                        .into(),
                )));
            }
        }
    };
    Ok(container
        .add_signature_xml(signature.into_xml())
        .name
        .clone())
}

pub struct ValidationPolicy {
    /// The underlying XAdES validation options.
    pub options: xades::ValidationOptions,
    /// Require Baseline LT (timestamp + revocation proof).
    /// Defaults to true.
    pub require_lt: bool,
}

impl Default for ValidationPolicy {
    fn default() -> Self {
        Self {
            options: xades::ValidationOptions {
                required_profile: Some(xades::Profile::LT),
                ..xades::ValidationOptions::default()
            },
            require_lt: true,
        }
    }
}

impl ValidationPolicy {
    /// Add trust anchors from PEM data (may contain several certificates).
    pub fn add_trusted_pem(&mut self, pem: &[u8]) -> Result<()> {
        self.options.add_trusted_pem(pem)?;
        Ok(())
    }
}

/// One signature with its validation result.
#[derive(Debug)]
pub struct SignatureResult {
    /// Name of the signature document.
    pub document: String,
    /// The XAdES validation outcome.
    /// Policy violations are appended to its `errors`.
    pub validation: xades::SignatureValidation,
}

impl SignatureResult {
    pub fn is_valid(&self) -> bool {
        self.validation.is_valid()
    }
}

/// Container validity verdict.
#[derive(Debug)]
pub struct ValidationReport {
    pub signatures: Vec<SignatureResult>,
    pub container_warnings: Vec<String>,
}

impl ValidationReport {
    /// True when the container has at least one signature and every
    /// signature satisfies both the cryptographic checks and the policy.
    pub fn all_valid(&self) -> bool {
        !self.signatures.is_empty() && self.signatures.iter().all(|s| s.is_valid())
    }
}

/// Validate every signature in the container under the given policy.
pub fn validate_container(
    container: &asic_e::Container,
    policy: &ValidationPolicy,
) -> Result<ValidationReport> {
    let files = data_objects(container);
    let mut report = ValidationReport {
        signatures: Vec::new(),
        container_warnings: container.warnings().to_vec(),
    };
    if container.signatures().is_empty() {
        report
            .container_warnings
            .push("container has no signatures".into());
    }

    for doc in container.signatures() {
        for mut validation in xades::validate(&doc.xml, &files, &policy.options)? {
            if policy.require_lt && !matches!(validation.profile, xades::Profile::LT) {
                validation.errors.push(format!(
                    "signature level {:?} does not meet the required Baseline LT",
                    validation.profile
                ));
            }
            report.signatures.push(SignatureResult {
                document: doc.name.clone(),
                validation,
            });
        }
    }
    Ok(report)
}

/// The Estonian profile requires the `mimetype` entry.
fn container_open_options() -> asic_e::OpenOptions {
    asic_e::OpenOptions {
        require_mimetype: true,
        ..asic_e::OpenOptions::default()
    }
}

/// Open a container file and validate it.
pub fn validate_file(
    path: impl AsRef<std::path::Path>,
    policy: &ValidationPolicy,
) -> Result<ValidationReport> {
    let container = asic_e::Container::open_file_with(path, &container_open_options())?;
    validate_container(&container, policy)
}

/// Validate a container from a byte buffer.
pub fn validate_bytes(bytes: &[u8], policy: &ValidationPolicy) -> Result<ValidationReport> {
    let container = asic_e::Container::from_bytes_with(bytes, &container_open_options())?;
    validate_container(&container, policy)
}

/// Convert container data files into the `DataObject` required by `xades`.
pub fn data_objects(container: &asic_e::Container) -> Vec<DataObject<'_>> {
    container
        .data_files()
        .iter()
        .map(|f| DataObject {
            name: &f.name,
            mime_type: &f.mime_type,
            content: &f.content,
        })
        .collect()
}
