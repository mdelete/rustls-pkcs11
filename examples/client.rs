extern crate rustls_pkcs11;

use env_logger::Env;
use regex::Regex;
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer, pki_types::pem::PemObject};
use rustls_pkcs11::PKCS11ClientCertResolver;
use std::{error::Error, sync::Arc};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::Builder::from_env(Env::default().default_filter_or("debug")).init();

    let pin_string = rpassword::prompt_password("PIN> ").unwrap();
    let re = Regex::new(r"^[0-9]{6}$").unwrap();
    let Some(capture) = re.captures(pin_string.as_str()) else {
        return Ok(());
    };
    let pin = Some(&capture[0]);
    let path = std::env::var("PKCS11_MODULE_PATH").unwrap_or_default();

    let mut root_certs = RootCertStore::empty();

    let cacert = CertificateDer::from_pem_slice(include_bytes!("certs/ca-rsa.pem")).unwrap();
    root_certs.add(cacert).unwrap();
    let cacert = CertificateDer::from_pem_slice(include_bytes!("certs/ca-ec.pem")).unwrap();
    root_certs.add(cacert).unwrap();

    let tls = ClientConfig::builder()
        .with_root_certificates(root_certs)
        .with_client_cert_resolver(Arc::new(
            PKCS11ClientCertResolver::new(pin, path.as_ref()).unwrap(),
        ));

    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .build()?;

    let response = client
        .get("https://localhost:8080")
        .send()
        .await?
        .text()
        .await?;
    println!("{}", response);

    Ok(())
}
