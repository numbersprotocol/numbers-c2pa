from datetime import datetime

from numbers_c2pa import create_c2pa_manifest, inject_file

if __name__ == '__main__':
    with open('examples/es256_private.key') as f:
        private_key = f.read()
    with open('examples/es256_certs.pem') as f:
        sign_cert = f.read()
    manifest = create_c2pa_manifest(
        nid='bafkreicxvzt6xwmu6rrghe4bwixup5aqrw5abcskg5mpt2gnt2h7buwwzm',  # nid of numbers.png
        creator_name='Tester',
        creator_public_key='0x2FBfE8F2bA00B255e60c220755040B597d09aFFa',  # ethereum wallet address
        asset_hash='57ae67ebd994f462639381b22f47f4108dba008a4a3758f9e8cd9e8ff0d2d6cb',  # sha256sum of numbers.png
        date_created=datetime.now(),
        latitude='123.123',
        longitude='45.45',
        date_captured=None,
        digital_source_type='trainedAlgorithmicMedia',
        generated_by='Stable Diffusion',
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
