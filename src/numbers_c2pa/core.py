import base64
import binascii
import json
import mimetypes
import os
import subprocess  # nosec
from datetime import datetime
from decimal import Decimal
from tempfile import TemporaryDirectory
from typing import Any, Dict, List, Optional, Union

import requests

from .exceptions import NoClaimFound, UnknownError


def _mimetype_to_ext(asset_mime_type: str):
    ext = mimetypes.guess_extension(asset_mime_type)
    if not ext:
        raise ValueError(f'Could not find a file extension for MIME type: {asset_mime_type}')
    return ext


def format_claim_generator(name: str) -> str:
    """
    Claim generator must be underscore-separated Pascal case
    ex. Numbers_Protocol
    """
    # Split the name into words based on spaces or other delimiters
    words = name.replace('-', ' ').replace('_', ' ').split()

    # Capitalize each word and join with underscores
    return '_'.join(word.capitalize() for word in words)


def format_datetime(date: Optional[datetime], to_timestamp=False) -> Optional[Union[str, int]]:
    if not date:
        return None
    if to_timestamp:
        return int(date.timestamp())
    return date.strftime('%Y-%m-%dT%H:%M:%SZ')


def format_geolocation(value: Optional[str]) -> Optional[str]:
    return f'{Decimal(value):.12f}' if value else None


def c2patool_inject(
    file_path: str,
    manifest_path: str,
    output_path: str,
    force_overwrite: bool,
    *,
    parent_path: Optional[str] = None,
    private_key: Optional[str] = None,
    sign_cert: Optional[str] = None,
):
    env_vars = os.environ.copy()
    if private_key:
        env_vars['C2PA_PRIVATE_KEY'] = private_key
    if sign_cert:
        env_vars['C2PA_SIGN_CERT'] = sign_cert
    command = f"c2patool '{file_path}' -m '{manifest_path}' -o '{output_path}'"

    if parent_path:
        command += f" -p '{parent_path}'"
    if force_overwrite:
        command += ' -f'
    try:
        subprocess.run(
            command,
            shell=True,
            env=env_vars,
            check=True,
            stderr=subprocess.PIPE,
        )  # nosec
    except subprocess.CalledProcessError as e:
        raise UnknownError(e.stderr) from e


def create_assertion_asset_tree(
    asset_tree_cid: Optional[str] = None,
    asset_tree_sha256: Optional[str] = None,
    asset_tree_signature: Optional[str] = None,
    committer: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    if not asset_tree_cid or not asset_tree_sha256 or not asset_tree_signature or not committer:
        return None

    return {
        'label': 'io.numbersprotocol.asset-tree',
        'data': {
            'assetTreeCid': asset_tree_cid,
            'assetTreeSha256': asset_tree_sha256,
            'assetTreeSignature': asset_tree_signature,
            'committer': committer,
        }
    }


def create_assertion_creative_work(
    nid: str,
    creator_name: str,
    date_created: Optional[datetime] = None,
    location_created: Optional[str] = None,
):
    data = {
        '@context': 'https://schema.org',
        '@type': 'CreativeWork',
        'url': f'https://verify.numbersprotocol.io/asset-profile/{nid}',
        'identifier': nid,
    }
    if creator_name:
        data['author'] = [
            {
                '@type': 'Person',
                'name': creator_name,
            }
        ]
    if isinstance(date_created, datetime):
        data['dateCreated'] = date_created.strftime('%Y-%m-%dT%H:%M:%SZ')
    if location_created:
        data['locationCreated'] = location_created

    return {
        'label': 'stds.schema-org.CreativeWork',
        'data': data
    }


def create_c2pa_manifest(
    nid: str,
    creator_name: str,
    creator_public_key: str,
    asset_hash: str,
    *,
    date_created: Optional[datetime] = None,
    latitude: Optional[str] = None,
    longitude: Optional[str] = None,
    date_captured: Optional[datetime] = None,
    alg: str = 'es256',
    ta_url: str = 'http://timestamp.digicert.com',
    vendor: str = 'numbersprotocol',
    claim_generator_name: str = 'Numbers Protocol',
    digital_source_type: Optional[str] = None,
    generated_by: Optional[str] = None,
    asset_tree_cid: Optional[str] = None,
    asset_tree_sha256: Optional[str] = None,
    asset_tree_signature: Optional[str] = None,
    committer: Optional[str] = None,
):
    location_created = (
        f'{format_geolocation(latitude)}, {format_geolocation(longitude)}'
        if latitude and longitude else None
    )

    manifest = {
        'alg': alg,
        'ta_url': ta_url,
        'vendor': vendor,
        'claim_generator': format_claim_generator(claim_generator_name),
        'claim_generator_info': [
            {
                'name': claim_generator_name,
            },
        ],
        'title': nid,
        'assertions': [
            create_assertion_creative_work(
                nid, creator_name, date_created, location_created,
            ),
            {
                'label': 'c2pa.actions.v2',
                'data': {
                    'actions': [
                        create_action_c2pa_opened(
                            asset_hash, digital_source_type, generated_by,
                        ),
                    ],
                }
            },
            {
                'label': 'io.numbersprotocol.integrity',
                'data': {
                    'nid': nid,
                    'publicKey': creator_public_key,
                    'mediaHash': asset_hash,
                    'captureTimestamp': format_datetime(date_captured, to_timestamp=True),
                }
            },
            {
                'label': 'stds.exif',
                'data': {
                    '@context': {
                        'EXIF': 'http://ns.adobe.com/EXIF/1.0/',
                        'EXIFEX': 'http://cipa.jp/EXIF/2.32/',
                        'dc': 'http://purl.org/dc/elements/1.1/',
                        'rdf': 'http://www.w3.org/1999/02/22-rdf-syntax-ns#',
                        'tiff': 'http://ns.adobe.com/tiff/1.0/',
                        'xmp': 'http://ns.adobe.com/xap/1.0/'
                    },
                    'EXIF:GPSLatitude': format_geolocation(latitude),
                    'EXIF:GPSLongitude': format_geolocation(longitude),
                    "EXIF:GPSTimeStamp": format_datetime(date_captured),
                    'EXIF:DateTimeOriginal': format_datetime(date_captured),
                },
                'kind': 'Json'
            },
        ]
    }
    if assertion_asset_tree := create_assertion_asset_tree(
        asset_tree_cid, asset_tree_sha256, asset_tree_signature, committer,
    ):
        manifest['assertions'].append(assertion_asset_tree)
    return manifest


def create_custom_c2pa_manifest(
    *,
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


def create_action_c2pa_opened(
    asset_hex_hash: str,
    digital_source_type: Optional[str] = None,
    software_agent: Optional[str] = None,
) -> Dict[str, Any]:
    base64_hash = base64.b64encode(binascii.unhexlify(asset_hex_hash)).decode()
    action = {
        'action': 'c2pa.opened',
        'parameters': {
            'ingredients': [
                {
                    'url': 'self#jumbf=c2pa.assertions/c2pa.ingredient',
                    'alg': 'sha256',
                    'hash': base64_hash,
                },
            ],
        },
    }
    if digital_source_type:
        action['digitalSourceType'] = (
            'http://cv.iptc.org/newscodes/digitalsourcetype/'
            f'{digital_source_type}'
        )
    if software_agent:
        action['softwareAgent'] = {
            'name': software_agent,
        }
    return action


def inject(
    asset_bytes: bytes,
    asset_mime_type: str,
    manifest: Dict,
    *,
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
    *,
    parent_path: Optional[str] = None,
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
            response = requests.get(thumbnail_url, stream=True, timeout=120)
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
        with open(manifest_file_path, 'w',) as manifest_file:
            json.dump(manifest, manifest_file)
            manifest_file.flush()

        c2patool_inject(
            asset_file,
            manifest_file.name,
            c2pa_output_file,
            force_overwrite=force_overwrite,
            parent_path=parent_path,
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
        process = subprocess.run(
            command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False
        )  # nosec
        if process.returncode != 0:
            if 'No claim found' in process.stderr:
                raise NoClaimFound
            raise UnknownError(process.stderr)

        json_output = json.loads(process.stdout)
        return json_output


def read_c2pa_file(c2pa_file: str):
    command = ['c2patool', c2pa_file]
    process = subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)  # nosec
    if process.returncode != 0:
        if 'No claim found' in process.stderr:
            raise NoClaimFound
        raise UnknownError(process.stderr)

    json_output = json.loads(process.stdout)
    return json_output
