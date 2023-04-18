import json
import mimetypes
import os
import subprocess
from datetime import datetime
from tempfile import TemporaryDirectory
from typing import Dict, Optional


def _mimetype_to_ext(asset_mime_type: str):
    ext = mimetypes.guess_extension(asset_mime_type)
    if not ext:
        raise ValueError(f'Could not find a file extension for MIME type: {asset_mime_type}')
    return ext


def create_c2pa_manifest(
    nid: str,
    creator_public_key: str,
    asset_hash: str,
    date_created: datetime,
    location_created: str,
    date_captured: Optional[datetime],
    alg: str = 'es256',
    ta_url: str = 'http://timestamp.digicert.com',
    claim_generator: str = 'Numbers_Protocol',
):
    captureTimestamp = date_captured.timestamp() if date_captured else None
    manifest = {
        'alg': alg,
        'ta_url': ta_url,
        'claim_generator': claim_generator,
        'title': nid,
        'assertions': [
            {
                'label': 'stds.schema-org.CreativeWork',
                'data': {
                    '@context': 'https://schema.org',
                    '@type': 'CreativeWork',
                    'author': [
                        {
                            '@type': 'Person',
                            'name': creator_public_key,
                        }
                    ],
                    'dateCreated': date_created.strftime('%Y-%m-%dT%H:%M:%SZ'),
                    'locationCreated': location_created,
                    'identifier': nid,
                }
            },
            {
                'label': 'numbers.integrity.json',
                'data': {
                    'nid': nid,
                    'publicKey': creator_public_key,
                    'mediaHash': asset_hash,
                    'captureTimestamp': captureTimestamp,
                }
            }
        ]
    }
    return manifest


def inject(
    asset_bytes: bytes,
    asset_mime_type: str,
    manifest: Dict,
    private_key: Optional[str] = None,
    sign_cert: Optional[str] = None,
    force_overwrite: bool = True,
):
    """Perform C2PA injection given in-memory asset file bytes using tempfile.
    """
    file_ext = _mimetype_to_ext(asset_mime_type)
    with TemporaryDirectory(prefix='temp_dir') as temp_dir:
        manifest_file = os.path.join(temp_dir, 'manifest.json')
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f)

        asset_file = os.path.join(temp_dir, f'asset.{file_ext}')
        with open(asset_file, 'wb') as f:
            f.write(asset_bytes)

        asset_c2pa_file = os.path.join(temp_dir, f'asset-c2pa.{file_ext}')
        env_vars = os.environ.copy()
        if private_key:
            env_vars['C2PA_PRIVATE_KEY'] = private_key
        if sign_cert:
            env_vars['C2PA_SIGN_CERT'] = sign_cert
        command = f'c2patool {asset_file} -m {manifest_file} -o {asset_c2pa_file}'
        if force_overwrite:
            command += ' -f'
        subprocess.run(
            command,
            shell=True,
            env=env_vars,
            check=True,
        )

        with open(asset_c2pa_file, 'rb') as f:
            asset_c2pa_bytes = f.read()
        return asset_c2pa_bytes


def inject_file(
    asset_file: str,
    manifest: Dict,
    private_key: Optional[str] = None,
    sign_cert: Optional[str] = None,
    force_overwrite: bool = True,
):
    """Perform C2PA injection given an existing asset file.
    """
    with TemporaryDirectory(prefix='temp_dir') as temp_dir:
        manifest_file = os.path.join(temp_dir, 'manifest.json')
        with open(manifest_file, 'w') as f:
            json.dump(manifest, f)

        # Create C2PA filename. The original filename should contain exactly one dot.
        asset_c2pa_file = asset_file.split('.')[0] + '-c2pa.' + asset_file.split('.')[1]
        env_vars = os.environ.copy()
        if private_key:
            env_vars['C2PA_PRIVATE_KEY'] = private_key
        if sign_cert:
            env_vars['C2PA_SIGN_CERT'] = sign_cert
        command = f'c2patool {asset_file} -m {manifest_file} -o {asset_c2pa_file}'
        if force_overwrite:
            command += ' -f'
        subprocess.run(
            command,
            shell=True,
            env=env_vars,
            check=True,
        )
