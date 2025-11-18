# numbers-c2pa


## Setup

Install Rust

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install c2patool

Download the prebuilt binary for your platform:

```bash
# For macOS (Universal Binary - Apple Silicon & Intel)
curl -L -o c2patool.zip https://github.com/contentauth/c2pa-rs/releases/download/c2patool-v0.26.1/c2patool-v0.26.1-universal-apple-darwin.zip
unzip c2patool.zip
chmod +x c2patool/c2patool
cp c2patool/c2patool ~/.local/bin/  # or any directory in your PATH

# For Linux
curl -L -o c2patool.tar.gz https://github.com/contentauth/c2pa-rs/releases/download/c2patool-v0.26.1/c2patool-v0.26.1-x86_64-unknown-linux-gnu.tar.gz
tar -xzf c2patool.tar.gz
chmod +x c2patool/c2patool
cp c2patool/c2patool ~/.local/bin/

# For Windows
# Download: https://github.com/contentauth/c2pa-rs/releases/download/c2patool-v0.26.1/c2patool-v0.26.1-x86_64-pc-windows-msvc.zip
# Extract and add c2patool.exe to your PATH

# Verify installation
c2patool --version  # Should show: c2patool 0.26.1
```

Alternatively, build from source (requires Rust):

```bash
$ cargo install c2patool --version 0.26.1
```

Install numbers-c2pa

```
$ python3 -m pip install git+https://github.com/numbersprotocol/numbers-c2pa.git
```

## Usage

C2PA Injection

```python
from datetime import datetime

from numbers_c2pa import create_c2pa_manifest, inject_file

if __name__ == '__main__':
    with open('examples/es256_private.key') as f:
        private_key = f.read()
    with open('examples/es256_certs.pem') as f:
        sign_cert = f.read()
    manifest = create_c2pa_manifest(
        nid='this is nid',
        creator_public_key='this is creator public key',
        asset_hash='this is sha256hash',
        date_created=datetime.now(),
        location_created='123.123, 45.45',
        date_captured=None,
    )
    inject_file(
        'examples/numbers.png',
        'examples/numbers-c2pa.png',
        manifest=manifest,
        parent_path='examples/numbers.png',
        private_key=private_key,
        sign_cert=sign_cert,
    )
    # examples/numbers-c2pa.png will be created
    # Upload file to https://verify.contentauthenticity.org/inspect to view C2PA data
```

Read C2PA data

```python
from numbers_c2pa import read_c2pa_file

if __name__ == '__main__':
    c2pa_json = read_c2pa_file('examples/numbers-c2pa.png')
    print(c2pa_json)

```

## Create self-signed certificate with intermediate CA

According to [c2patool](https://github.com/contentauth/c2patool#appendix-creating-and-using-an-x509-certificate) readme:

> Both the private_key and sign_cert must be in PEM format. The sign_cert must contain a PEM certificate chain starting with the end-entity certificate used to sign the claim ending with the intermediate certificate before the root CA certificate. See the sample folder for example certificates.

Using a intermediate CA certificate is required.

## Updated steps

Create end-entity and intermediate private keys

```bash
openssl ecparam -genkey -name prime256v1 -noout -out intermediate_ca.key
openssl ecparam -genkey -name prime256v1 -noout -out end_entity.key
```

Create intermediate cert

```bash
openssl req -x509 -new -key intermediate_ca.key -out intermediate_ca.crt -subj "/CN=Numbers Intermediate CA" -days 365 -sha256
```

Create `end_entity_csr.conf` file

```conf
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = v3_req
distinguished_name = dn

[ dn ]
C = US
ST = California
L = San Fransisco
O = Numbers Protocol
OU = Numbers Protocol
CN = Numbers Protocol

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = timeStamping
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = numbersprotocol.io
DNS.2 = www.numbersprotocol.io
```

Create end-entity CSR

```bash
openssl req -new -key end_entity.key -out end_entity.csr -config end_entity_csr.conf
```

Create end-entity certificate

```bash
openssl x509 -req -in end_entity.csr -CA intermediate_ca.crt -CAkey intermediate_ca.key -out end_entity.crt -days 365 -CAcreateserial -extfile end_entity_csr.conf -extensions v3_req -sha256
```

Combine certificate chain

```bash
cat end_entity.crt intermediate_ca.crt > certificate_chain.pem
```
