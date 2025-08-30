# rustls-pkcs11

Resolve rustls client certs with hardware security modules like YubiKey or smartcards using the PKCS11 standard.

Caution: Only tested with YubiKeys (ECDSA/RSA) and OpenPGP Card 3.4 so far on Linux and MacOS.

Currently supported signature algorithms:

* RSA_PKCS1_SHA256
* RSA_PKCS1_SHA384
* ECDSA_NISTP256_SHA256
* ECDSA_NISTP384_SHA384

## Usage example

```
  ...
    let pin = Some("1234");
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(root_certs)
        .with_client_cert_resolver(Arc::new(
            PKCS11ClientCertResolver::new(pin, "/path/to/opensc-pkcs11.so").unwrap(),
        ));
  ...
```

## Testing the example with openssl s_server

Set the environment variable ```PKCS11_MODULE_PATH``` to your the absolute path of your PKCS11-lib (like libykcs11 or opensc).

Example (YubiKey on MacOS):
```
export PKCS11_MODULE_PATH=/usr/local/lib/libykcs11.dylib
```

Example (OpenSC installed with Homebrew on MacOS):
```
export PKCS11_MODULE_PATH=/opt/homebrew/lib/opensc-pkcs11.so
```

Example (OpenSC installed with pacman on manjaro):
```
export PKCS11_MODULE_PATH=/usr/lib/opensc-pkcs11.so
```

### ECDSA

Change directory to ```examples/certs```.
Start in a separate terminal window:

```
openssl s_server -trace -CAfile ca-ec.pem -cert server-ec.pem -key server-ec.key -Verify 1 -www -port 8080
```

Load client-ec.p12 into your HSM (Passwort: 'letmein').

```
cargo run --example client
```

Type in your HSM Pin at the prompt (assuming 6 digits).

### RSA

Change directory to ```examples/certs```.
Start in a separate terminal window:

```
openssl s_server -trace -CAfile ca-rsa.pem -cert server-rsa.pem -key server-rsa.key -Verify 1 -tls1_2 -www -port 8080
```

Load client-rsa.p12 into your HSM (Passwort: 'letmein').

```
cargo run --example client
```

Type in your HSM Pin at the prompt (assuming 6 digits).

## OpenPGP Card

You can use an OpenPGP Card in a smart card slot of your Thinkpad or similar to authenticate rustls client connections. This has been tested with an OpenPGP Card 3.4 (RSA-2048 only).

The procedure for installing the certificate is straighforward but a little bit weird, but maybe [this](https://github.com/OpenSC/OpenSC/wiki/OpenPGP-card) information is also a bit outdated.

Installing the certificate is only possible in ID 3, this is normally the authentication slot. For use with TLS the information has to be available under ID 1, the signing slot. To achive this, the private key has to be uploaded to ID 1 as well, using the ADMIN pin and by using the auth-ID 3.

At first, we need to extract the private key from the test bundle:
```
openssl pkcs12 -in client-rsa.p12 -out client-rsa.key -nodes -nocerts
```

Then load the bundle to id 3 with auth-id 3, giving the ADMIN pin:
```
pkcs15-init --delete-objects privkey,pubkey --id 3 --store-private-key client-rsa.p12 --format pkcs12 --auth-id 3 --verify-pin
```

Then the private key to id 1, again with auth-id 3, again giving the ADMIN pin. This seems to connect those somehow:
```
pkcs15-init --delete-objects privkey,pubkey --id 1 --store-private-key client-rsa.key --auth-id 3 --verify-pin
```

When running the example, you need to supply the USER pin.
