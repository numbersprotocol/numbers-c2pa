# numbers-c2pa


## Setup

Install Rust

```bash
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Install c2patool

```bash
$ cargo install c2patool
```

Install numbers-c2pa

```
$ python3 -m pip install git+https://github.com/numbersprotocol/numbers-c2pa.git
```

## Create self-signed certificate with intermediate CA

According to [c2patool](https://github.com/contentauth/c2patool#appendix-creating-and-using-an-x509-certificate) readme:

> Both the private_key and sign_cert must be in PEM format. The sign_cert must contain a PEM certificate chain starting with the end-entity certificate used to sign the claim ending with the intermediate certificate before the root CA certificate. See the sample folder for example certificates.

Using a intermediate CA certificate is required.
