# rustls-pkcs11

Resolve rustls client certs with hardware security modules like YubiKey or smartcards using the PKCS11 standard.

Caution: Only tested with (old) YubiKeys (ECDSA/RSA) so far.

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

Example (YubiKey on MacOs):
```
export PKCS11_MODULE_PATH=/usr/local/lib/libykcs11.dylib
```

Example (OpenSC installed with Homebrew on MacOS):
```
export PKCS11_MODULE_PATH=/opt/homebrew/lib/opensc-pkcs11.so
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
