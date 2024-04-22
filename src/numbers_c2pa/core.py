import json
import mimetypes
import os
import subprocess
from datetime import datetime
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional

import requests

from .exceptions import NoClaimFound, UnknownError


def _mimetype_to_ext(asset_mime_type: str):
    ext = mimetypes.guess_extension(asset_mime_type)
    if not ext:
        raise ValueError(f'Could not find a file extension for MIME type: {asset_mime_type}')
    return ext


def c2patool_inject(
    file_path: str,
    manifest_path: str,
    output_path: str,
    force_overwrite: bool,
    private_key: Optional[str] = None,
    sign_cert: Optional[str] = None,
):
    env_vars = os.environ.copy()
    if private_key:
        env_vars['C2PA_PRIVATE_KEY'] = private_key
    if sign_cert:
        env_vars['C2PA_SIGN_CERT'] = sign_cert
    command = f"c2patool '{file_path}' -m '{manifest_path}' -o '{output_path}'"

    if force_overwrite:
        command += ' -f'
    try:
        subprocess.run(
            command,
            shell=True,
            env=env_vars,
            check=True,
            stderr=subprocess.PIPE,
        )
    except subprocess.CalledProcessError as e:
        raise UnknownError(e.stderr)


def create_c2pa_manifest(
    nid: str,
    creator_public_key: str,
    asset_hash: str,
    date_created: datetime,
    location_created: str,
    date_captured: Optional[datetime],
    alg: str = 'es256',
    ta_url: str = 'http://timestamp.digicert.com',
    vendor: str = 'numbersprotocol',
    claim_generator: str = 'Numbers_Protocol',
    digital_source_type: Optional[str] = None,
    generated_by: Optional[str] = None,
):
    captureTimestamp = date_captured.timestamp() if date_captured else None
    manifest = {
        'alg': alg,
        'ta_url': ta_url,
        'vendor': vendor,
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
                'label': 'c2pa.actions',
                'data': {
                    'actions': [
                        {
                            'action': 'c2pa.opened',
                        }
                    ],
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
    if digital_source_type:
        manifest['assertions'][1]['data']['actions'][0].update({
            'digitalSourceType': f'http://cv.iptc.org/newscodes/digitalsourcetype/{digital_source_type}',
        })
    if generated_by:
        manifest['assertions'][1]['data']['actions'][0].update({
            'softwareAgent': f'{generated_by}'
        })
    return manifest


def create_custom_c2pa_manifest(
    alg: str = 'es256',
    ta_url: str = 'http://timestamp.digicert.com',
    vendor: str = 'numbersprotocol',
    claim_generator: str = 'Numbers_Protocol',
    title: Optional[str] = None,
    author_type: str = 'Person',
    author_credential: Optional[List] = None,
    author_identifier: Optional[str] = None,
    author_name: Optional[str] = None,
    c2pa_actions: Optional[List] = None,
    custom_assertions: Optional[List] = None,
):
    manifest = {
        'alg': alg,
        'ta_url': ta_url,
        'vendor': vendor,
        'claim_generator': claim_generator,
        'title': title,
        'assertions': [
            {
                'label': 'stds.schema-org.CreativeWork',
                'data': {
                    '@context': 'https://schema.org',
                    '@type': 'CreativeWork',
                    'author': [
                        {
                            '@type': author_type,
                            'credential': author_credential or [],
                            'identifier': author_identifier,
                            'name': author_name,
                        }
                    ],
                }
            },
        ]
    }
    manifest = {k: v for k, v in manifest.items() if v is not None}
    if c2pa_actions:
        manifest['assertions'].append(
            {
                'label': 'c2pa.actions',
                'data':
                {
                    'actions': c2pa_actions,
                }
            }
        )
    if custom_assertions:
        manifest['assertions'] += custom_assertions
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
        c2patool_inject(
            asset_file,
            manifest_file,
            asset_c2pa_file,
            force_overwrite=force_overwrite,
            private_key=private_key,
            sign_cert=sign_cert,
        )

        with open(asset_c2pa_file, 'rb') as f:
            asset_c2pa_bytes = f.read()
        return asset_c2pa_bytes


def inject_file(
    asset_file: str,
    c2pa_output_file: str,
    manifest: Dict[str, Any],
    private_key: Optional[str] = None,
    sign_cert: Optional[str] = None,
    force_overwrite: bool = True,
    thumbnail_url: Optional[str] = None,
):
    """Perform C2PA injection given an existing asset file.
    """
    with TemporaryDirectory() as temp_dir:
        if thumbnail_url:
            thumbnail_file_path = os.path.join(temp_dir, 'thumbnail.jpg')
            response = requests.get(thumbnail_url, stream=True)
            response.raise_for_status()
            with open(thumbnail_file_path, 'wb') as thumbnail_file:
                for chunk in response.iter_content(chunk_size=8192):
                    thumbnail_file.write(chunk)
                thumbnail_file.flush()
            manifest['thumbnail'] = {
                'format': 'image/jpeg',
                'identifier': thumbnail_file_path,
            }

        # Save the manifest to a temporary file
        manifest_file_path = os.path.join(temp_dir, 'manifest.json')
        with open(manifest_file_path, 'w') as manifest_file:
            json.dump(manifest, manifest_file)
            manifest_file.flush()

        c2patool_inject(
            asset_file,
            manifest_file.name,
            c2pa_output_file,
            force_overwrite=force_overwrite,
            private_key=private_key,
            sign_cert=sign_cert,
        )


def read_c2pa(asset_c2pa_bytes: bytes, asset_mime_type: str):
    file_ext = _mimetype_to_ext(asset_mime_type)
    with TemporaryDirectory(prefix='temp_dir') as temp_dir:
        asset_c2pa_file = os.path.join(temp_dir, f'asset-c2pa.{file_ext}')
        with open(asset_c2pa_file, 'wb') as f:
            f.write(asset_c2pa_bytes)

        command = ['c2patool', asset_c2pa_file]
        process = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        if process.returncode != 0:
            if 'No claim found' in process.stderr:
                raise NoClaimFound
            else:
                raise UnknownError(process.stderr)

        json_output = json.loads(process.stdout)
        return json_output


def read_c2pa_file(c2pa_file: str):
    command = ['c2patool', c2pa_file]
    process = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if process.returncode != 0:
        if 'No claim found' in process.stderr:
            raise NoClaimFound
        else:
            raise UnknownError(process.stderr)

    json_output = json.loads(process.stdout)
    return json_output
