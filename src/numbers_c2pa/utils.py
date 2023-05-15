import datetime
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def generate_es256_private_key():
    # Generate an ES256 private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Serialize the private key to PEM format
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def create_es256_private_key_file(
    private_key_pem: Optional[bytes] = None,
    output_file='es256_private_key.pem'
):
    if not private_key_pem:
        private_key_pem = generate_es256_private_key()
    # Save the private key PEM to a file
    with open(output_file, 'wb') as f:
        f.write(private_key_pem)


def create_self_signed_certificate(private_key_pem, output_file='es256_certs.pem'):
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
    )

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, 'US'),
        # x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        # x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, 'Numbers Protocol'),
        x509.NameAttribute(NameOID.COMMON_NAME, 'numbersprotocol.io'),
    ])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(u"my-organization.com")]),
            critical=False,
        )
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )
        .sign(private_key, hashes.SHA256())
    )

    certificate_pem = certificate.public_bytes(serialization.Encoding.PEM)

    with open(output_file, 'wb') as f:
        f.write(certificate_pem)
