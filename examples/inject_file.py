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
        manifest=manifest,
        private_key=private_key,
        sign_cert=sign_cert,
    )
    # examples/numbers-c2pa.png will be created
    # Upload file to https://verify.contentauthenticity.org/inspect to view C2PA data
