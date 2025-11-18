import base64
import binascii
import json
import mimetypes
import os
import subprocess  # nosec
from datetime import datetime
from decimal import Decimal
from tempfile import TemporaryDirectory
from typing import Any, Dict, Optional, Union

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


def format_geolocation(value: Optional[str], is_latitude: bool) -> Optional[str]:
    if not value:
        return None
    d = Decimal(value)
    # Validate coordinate ranges - return None for invalid values to skip EXIF field
    if is_latitude and not (-90 <= d <= 90):
        return None
    if not is_latitude and not (-180 <= d <= 180):
        return None
    degrees = int(abs(d))
    minutes = (abs(d) - degrees) * 60
    if is_latitude:
        direction = 'N' if d >= 0 else 'S'
    else:
        direction = 'E' if d >= 0 else 'W'
    return f'{degrees},{minutes:.4f}{direction}'


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


def create_assertion_metadata(
    nid: str,
    date_created: Optional[datetime] = None,
    latitude: Optional[str] = None,
    longitude: Optional[str] = None,
    date_captured: Optional[datetime] = None,
):
    metadata = {
        '@context': {
            'dc': 'http://purl.org/dc/elements/1.1/',
            'Iptc4xmpCore': 'http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/',
            'Iptc4xmpExt': 'http://iptc.org/std/Iptc4xmpExt/2008-02-29/',
            'exif': 'http://ns.adobe.com/exif/1.0/',
            'exifEX': 'http://cipa.jp/exif/2.32/',
            'tiff': 'http://ns.adobe.com/tiff/1.0/',
            'xmp': 'http://ns.adobe.com/xap/1.0/'
        },
        'dc:identifier': nid,
    }
    if isinstance(date_created, datetime):
        metadata['dc:date'] = date_created.strftime('%Y-%m-%dT%H:%M:%SZ')
    if latitude and longitude:
        formatted_lat = format_geolocation(latitude, True)
        formatted_lon = format_geolocation(longitude, False)
        if formatted_lat and formatted_lon:
            metadata['exif:GPSLatitude'] = formatted_lat
            metadata['exif:GPSLongitude'] = formatted_lon
    if isinstance(date_captured, datetime):
        metadata['exif:GPSTimeStamp'] = date_captured.strftime('%H:%M:%S')
        metadata['exif:DateTimeOriginal'] = date_captured.strftime('%Y:%m:%d %H:%M:%S')

    return {
        'label': 'c2pa.metadata',
        'data': metadata
    }


def create_c2pa_manifest(
    nid: str,
    creator_public_key: str,
    asset_hash: str,
    *,
    date_created: Optional[datetime] = None,
    latitude: Optional[str] = None,
    longitude: Optional[str] = None,
    date_captured: Optional[datetime] = None,
    creator_name: Optional[str] = None,
    alg: str = 'es256',
    ta_url: str = 'http://timestamp.digicert.com',
    vendor: str = 'numbersprotocol',
    claim_generator_name: str = 'Numbers Protocol',
    claim_generator_version: Optional[str] = None,
    digital_source_type: Optional[str] = None,
    generated_by: Optional[str] = None,
    asset_tree_cid: Optional[str] = None,
    asset_tree_sha256: Optional[str] = None,
    asset_tree_signature: Optional[str] = None,
    committer: Optional[str] = None,
):
    claim_generator_info = {'name': claim_generator_name}
    if claim_generator_version:
        claim_generator_info['version'] = claim_generator_version

    manifest = {
        'alg': alg,
        'ta_url': ta_url,
        'vendor': vendor,
        'claim_generator': format_claim_generator(claim_generator_name),
        'claim_generator_info': [claim_generator_info],
        'title': nid,
        'assertions': [
            create_assertion_metadata(
                nid, date_created, latitude, longitude, date_captured,
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
                    **({'creatorName': creator_name} if creator_name else {}),
                }
            },
        ]
    }
    if assertion_asset_tree := create_assertion_asset_tree(
        asset_tree_cid, asset_tree_sha256, asset_tree_signature, committer,
    ):
        manifest['assertions'].append(assertion_asset_tree)
    return manifest


def create_action_c2pa_opened(
    asset_hex_hash: str,
    digital_source_type: Optional[str] = None,
    software_agent: Optional[str] = None,
) -> Dict[str, Any]:
    """Create a c2pa.opened action with ingredient reference.

    Args:
        asset_hex_hash: Hex-encoded SHA256 hash of the asset
        digital_source_type: Digital source type. Can be either:
            - Short form (e.g., 'trainedAlgorithmicMedia', 'digitalCapture', 'negativeFilm'):
                The IPTC namespace 'http://cv.iptc.org/newscodes/digitalsourcetype/' will be prepended.
                Example: 'trainedAlgorithmicMedia' →
                    'http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia'
            - Full URI (starting with 'http://' or 'https://'):
                Used as-is. Can be from any namespace (IPTC or C2PA).
                Examples: 'http://cv.iptc.org/newscodes/digitalsourcetype/digitalCapture'
                         'http://c2pa.org/digitalsourcetype/empty'
            See IPTC NewsCodes: https://cv.iptc.org/newscodes/digitalsourcetype/
        software_agent: Name of the software that created/modified the asset

    Returns:
        Action dictionary with ingredient reference for c2pa.actions.v2
    """
    base64_hash = base64.b64encode(binascii.unhexlify(asset_hex_hash)).decode()

    # Create action with ingredients reference (plural, as array)
    # c2patool 0.26+ uses c2pa.ingredient.v3 label
    action = {
        'action': 'c2pa.opened',
        'parameters': {
            'ingredients': [
                {
                    'url': 'self#jumbf=c2pa.assertions/c2pa.ingredient.v3',
                    'alg': 'sha256',
                    'hash': base64_hash,
                },
            ],
        },
    }
    if digital_source_type:
        # If full URI provided, use as-is; otherwise prepend IPTC namespace
        if digital_source_type.startswith(('http://', 'https://')):
            action['digitalSourceType'] = digital_source_type
        else:
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
