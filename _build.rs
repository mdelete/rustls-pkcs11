#![allow(clippy::uninlined_format_args)]

//! A program that generates ca certs, certs verified by the ca, and public
//! and private keys.

//! this has mostly been taken from the openssl crate

use std::fs;

use openssl::asn1::Asn1Time;
use openssl::bn::{BigNum, MsbOption};
use openssl::ec::{EcGroup, EcKey};
use openssl::error::ErrorStack;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::pkcs12::Pkcs12;
use openssl::pkey::{PKey, PKeyRef, Private};
use openssl::rsa::Rsa;
use openssl::x509::extension::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectAlternativeName,
    SubjectKeyIdentifier,
};
use openssl::x509::{X509, X509NameBuilder, X509Ref, X509Req, X509ReqBuilder, X509VerifyResult};

enum Usage {
    SERVER,
    CLIENT,
}

/// Make a CA certificate and private key
fn mk_ca_cert(key_pair: &PKey<Private>, cn: &str) -> Result<X509, ErrorStack> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "DE")?;
    x509_name.append_entry_by_text("ST", "HH")?;
    x509_name.append_entry_by_text("O", "Example Org")?;
    x509_name.append_entry_by_text("CN", cn)?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .key_cert_sign()
            .crl_sign()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

/// Make a X509 request with the given private key
fn mk_request(key_pair: &PKey<Private>, cn: &str) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(key_pair)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "DE")?;
    x509_name.append_entry_by_text("ST", "HH")?;
    x509_name.append_entry_by_text("O", "Example Org")?;
    x509_name.append_entry_by_text("CN", cn)?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;

    req_builder.sign(key_pair, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

/// Make a certificate and private key signed by the given CA cert and private key
fn mk_ca_signed_cert(
    ca_cert: &X509Ref,
    ca_key_pair: &PKeyRef<Private>,
    key_pair: &PKey<Private>,
    usage: Usage,
) -> Result<X509, ErrorStack> {
    let req = match usage {
        Usage::SERVER => mk_request(key_pair, "localhost")?,
        Usage::CLIENT => mk_request(key_pair, "client")?,
    };

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(&key_pair)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(365)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(
        KeyUsage::new()
            .critical()
            .non_repudiation()
            .digital_signature()
            .key_encipherment()
            .build()?,
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    match usage {
        Usage::SERVER => {
            let subject_alt_name = SubjectAlternativeName::new()
                .dns("localhost")
                .dns("localhost.localdomain")
                .ip("127.0.0.1")
                .ip("::1")
                .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
            cert_builder.append_extension(subject_alt_name)?;
            let extened_usage = ExtendedKeyUsage::new().server_auth().build()?;
            cert_builder.append_extension(extened_usage)?;
        }
        Usage::CLIENT => {
            let extened_usage = ExtendedKeyUsage::new().client_auth().build()?;
            cert_builder.append_extension(extened_usage)?;
        }
    }

    cert_builder.sign(ca_key_pair, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

fn real_main() -> Result<(), ErrorStack> {
    // create a RSA ca cert
    let rsa = Rsa::generate(2048)?;
    let ca_rsa_key_pair = PKey::from_rsa(rsa)?;
    let ca_rsa_cert = mk_ca_cert(&ca_rsa_key_pair, "Example CA with RSA")?;
    let ca_rsa_pem = ca_rsa_cert.to_pem().unwrap();
    fs::write("examples/certs/ca-rsa.pem", ca_rsa_pem).unwrap();

    // create an EC ca cert
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
    let key = EcKey::generate(&group)?;
    let ca_ec_key_pair = PKey::from_ec_key(key)?;
    let ca_ec_cert = mk_ca_cert(&ca_ec_key_pair, "Example CA with ECDSA")?;
    let ca_ec_pem = ca_ec_cert.to_pem().unwrap();
    fs::write("examples/certs/ca-ec.pem", ca_ec_pem).unwrap();

    // create a RSA server cert
    let rsa = Rsa::generate(2048)?;
    let server_key_pair = PKey::from_rsa(rsa)?;
    let server_cert = mk_ca_signed_cert(
        &ca_rsa_cert,
        &ca_rsa_key_pair,
        &server_key_pair,
        Usage::SERVER,
    )?;

    match ca_rsa_cert.issued(&server_cert) {
        X509VerifyResult::OK => println!("Certificate verified!"),
        ver_err => println!("Failed to verify certificate: {}", ver_err),
    };

    let server_pem = server_cert.to_pem().unwrap();
    fs::write("examples/certs/server-rsa.pem", server_pem).unwrap();
    let server_key = server_key_pair.private_key_to_pem_pkcs8().unwrap();
    fs::write("examples/certs/server-rsa.key", server_key).unwrap();

    // create an EC server cert
    let key = EcKey::generate(&group)?;
    let server_key_pair = PKey::from_ec_key(key)?;
    let server_cert = mk_ca_signed_cert(
        &ca_ec_cert,
        &ca_ec_key_pair,
        &server_key_pair,
        Usage::SERVER,
    )?;

    match ca_ec_cert.issued(&server_cert) {
        X509VerifyResult::OK => println!("Certificate verified!"),
        ver_err => println!("Failed to verify certificate: {}", ver_err),
    };

    let server_pem = server_cert.to_pem().unwrap();
    fs::write("examples/certs/server-ec.pem", server_pem).unwrap();
    let server_key = server_key_pair.private_key_to_pem_pkcs8().unwrap();
    fs::write("examples/certs/server-ec.key", server_key).unwrap();

    // create a RSA client cert bundle
    let rsa = Rsa::generate(2048)?;
    let client_key_pair = PKey::from_rsa(rsa)?;
    let client_cert = mk_ca_signed_cert(
        &ca_rsa_cert,
        &ca_rsa_key_pair,
        &client_key_pair,
        Usage::CLIENT,
    )?;

    match ca_rsa_cert.issued(&client_cert) {
        X509VerifyResult::OK => println!("Certificate verified!"),
        ver_err => println!("Failed to verify certificate: {}", ver_err),
    };

    let pkcs12 = Pkcs12::builder()
        .name("client")
        .pkey(&client_key_pair)
        .cert(&client_cert)
        .build2("letmein")
        .unwrap();

    fs::write("examples/certs/client-rsa.p12", pkcs12.to_der().unwrap()).unwrap();

    // Create an EC client cert bundle
    let key = EcKey::generate(&group)?;
    let client_key_pair = PKey::from_ec_key(key)?;
    let client_cert = mk_ca_signed_cert(
        &ca_ec_cert,
        &ca_ec_key_pair,
        &client_key_pair,
        Usage::CLIENT,
    )?;

    match ca_ec_cert.issued(&client_cert) {
        X509VerifyResult::OK => println!("Certificate verified!"),
        ver_err => println!("Failed to verify certificate: {}", ver_err),
    };

    let pkcs12 = Pkcs12::builder()
        .name("client")
        .pkey(&client_key_pair)
        .cert(&client_cert)
        .build2("letmein")
        .unwrap();

    fs::write("examples/certs/client-ec.p12", pkcs12.to_der().unwrap()).unwrap();

    Ok(())
}

fn main() {
    match real_main() {
        Ok(()) => println!("Finished."),
        Err(e) => println!("Error: {}", e),
    };
}
