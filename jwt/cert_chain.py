from __future__ import annotations

import base64
import binascii
from typing import Any, cast

from .exceptions import InvalidKeyError
from .utils import base64url_decode

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.ed448 import Ed448PublicKey
except ModuleNotFoundError:  # pragma: no cover - exercised in no-crypto environments
    has_crypto = False
else:
    has_crypto = True


def _decode_thumbprint(value: str, sha1_hex: str, sha256_hex: str) -> bytes | None:
    """Decode a JWK thumbprint member into the raw fingerprint bytes.

    Three encodings occur in real-world JWKs:

    * RFC 7517 base64url of the raw digest (20/32 bytes);
    * plain hex digest (40/64 characters);
    * the legacy Auth0 form: base64url of the uppercase hex ASCII digest
      (40/64 bytes).

    Returns ``None`` when *value* is not shaped like a thumbprint, so opaque
    ``kid`` values are left untouched.
    """
    if not isinstance(value, str) or not value:
        return None

    try:
        decoded = base64url_decode(value)
    except (ValueError, binascii.Error):
        decoded = None
    if decoded is not None:
        if len(decoded) in (20, 32):
            return decoded
        try:
            as_hex = decoded.decode("ascii")
        except UnicodeDecodeError:
            as_hex = None
        if as_hex is not None and as_hex.upper() in (sha1_hex, sha256_hex):
            return bytes.fromhex(as_hex)

    try:
        hex_decoded = bytes.fromhex(value)
    except ValueError:
        return None
    if len(hex_decoded) in (20, 32):
        return hex_decoded
    return None


def _load_x5c_certificates(x5c: Any) -> list[x509.Certificate]:
    """Parse the ``x5c`` member into DER certificates, failing closed."""
    if not isinstance(x5c, list) or not x5c:
        raise InvalidKeyError(
            "The JWK 'x5c' member must be a non-empty list of base64-encoded "
            "DER certificates"
        )

    certificates: list[x509.Certificate] = []
    for index, entry in enumerate(x5c):
        if not isinstance(entry, str) or not entry:
            raise InvalidKeyError(
                f"The JWK 'x5c' entry at index {index} is not a base64-encoded "
                "DER certificate"
            )
        try:
            der_bytes = base64.b64decode(entry, validate=True)
            certificate = x509.load_der_x509_certificate(der_bytes)
        except (ValueError, binascii.Error, UnsupportedAlgorithm) as error:
            raise InvalidKeyError(
                f"The JWK 'x5c' entry at index {index} is not a valid DER "
                f"certificate: {error}"
            ) from error
        certificates.append(certificate)
    return certificates


def _verify_certificate_signature(
    certificate: x509.Certificate, issuer_public_key: Any
) -> None:
    """Verify *certificate* against *issuer_public_key*, supporting the key
    types PyJWT can load."""
    hash_algorithm = certificate.signature_hash_algorithm
    if hash_algorithm is None and not isinstance(
        issuer_public_key, (Ed25519PublicKey, Ed448PublicKey)
    ):
        raise InvalidKeyError(
            "The JWK 'x5c' certificate chain uses an unsupported signature algorithm"
        )
    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            assert hash_algorithm is not None
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            assert hash_algorithm is not None
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(hash_algorithm),
            )
        elif isinstance(issuer_public_key, (Ed25519PublicKey, Ed448PublicKey)):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
        else:
            raise InvalidKeyError(
                "The JWK 'x5c' chain is signed with an unsupported key type: "
                f"{type(issuer_public_key).__name__}"
            )
    except (InvalidSignature, UnsupportedAlgorithm, TypeError) as error:
        raise InvalidKeyError(
            "The JWK 'x5c' certificate chain contains an invalid signature"
        ) from error


def _verify_chain(certificates: list[x509.Certificate]) -> None:
    """Check chain linkage (name chaining and cryptographic signatures)."""
    for index, certificate in enumerate(certificates):
        if index == len(certificates) - 1:
            break
        issuer_certificate = certificates[index + 1]
        if certificate.issuer != issuer_certificate.subject:
            raise InvalidKeyError(
                "The JWK 'x5c' certificate chain is not linked: the certificate "
                f"at index {index} was not issued by the certificate at index "
                f"{index + 1}"
            )
        _verify_certificate_signature(certificate, issuer_certificate.public_key())

    root = certificates[-1]
    if root.issuer == root.subject:
        # A self-signed trust anchor (including a single-certificate chain)
        # must itself carry a valid signature.
        _verify_certificate_signature(root, root.public_key())


def _public_key_bytes(public_key: Any) -> bytes:
    return cast(
        bytes,
        public_key.public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ),
    )


def _verify_thumbprints(jwk_data: dict[str, Any], leaf: x509.Certificate) -> None:
    """Bind the explicit thumbprint members to the leaf certificate.

    ``x5t`` and ``x5t#S256`` are defined as certificate thumbprints, so they
    are always checked. ``kid`` is an opaque identifier per RFC 7517; it is
    only checked when the JWK itself asserts that it equals a thumbprint
    member (i.e. ``kid`` is copied verbatim from ``x5t``/``x5t#S256``).
    """
    sha1 = leaf.fingerprint(hashes.SHA1())
    sha256 = leaf.fingerprint(hashes.SHA256())

    expected = {20: sha1, 32: sha256}
    sha1_hex = sha1.hex().upper()
    sha256_hex = sha256.hex().upper()
    for member in ("x5t", "x5t#S256"):
        if member not in jwk_data:
            continue
        actual = _decode_thumbprint(jwk_data[member], sha1_hex, sha256_hex)
        if actual is None:
            raise InvalidKeyError(
                f"The JWK {member!r} is not a valid certificate thumbprint"
            )
        if actual != expected[len(actual)]:
            raise InvalidKeyError(
                f"The JWK {member!r} does not match the thumbprint of the "
                "leaf certificate in 'x5c'"
            )

    kid = jwk_data.get("kid")
    if kid is not None and kid in (
        jwk_data.get("x5t"),
        jwk_data.get("x5t#S256"),
    ):
        actual = _decode_thumbprint(kid, sha1_hex, sha256_hex)
        if actual is not None and actual != expected[len(actual)]:
            raise InvalidKeyError(
                "The JWK 'kid' does not match the thumbprint of the leaf "
                "certificate in 'x5c'"
            )


def _verify_key_use(jwk_data: dict[str, Any], leaf: x509.Certificate) -> None:
    """Cross-check the JWK ``use`` against the certificate's key usage."""
    use = jwk_data.get("use")
    if use not in ("sig", "enc"):
        return

    try:
        extension = leaf.extensions.get_extension_for_class(x509.KeyUsage)
    except x509.ExtensionNotFound:
        return
    key_usage = extension.value

    if use == "sig" and not (
        key_usage.digital_signature
        or key_usage.content_commitment
        or key_usage.key_agreement
    ):
        raise InvalidKeyError(
            "The JWK 'use' is 'sig' but the leaf certificate's key usage "
            "does not permit digital signatures"
        )
    if use == "enc" and not (
        key_usage.key_encipherment
        or key_usage.data_encipherment
        or key_usage.key_agreement
    ):
        raise InvalidKeyError(
            "The JWK 'use' is 'enc' but the leaf certificate's key usage "
            "does not permit key exchange or encipherment"
        )


def validate_jwk_certificate_binding(jwk_data: dict[str, Any], public_key: Any) -> None:
    """Bind a JWK's ``x5c`` certificate chain to a single verifiable public
    key identity.

    The JWK may combine an ``x5c`` chain, inline key parameters (``n``/``e``
    or ``x``/``y``), ``kid``/thumbprints and an algorithm that were produced
    independently. Every identity-bearing member must agree on the leaf
    certificate's public key; any disagreement fails closed with
    :class:`~jwt.exceptions.InvalidKeyError`.

    :param jwk_data: The decoded JWK dictionary.
    :param public_key: The key object built from the JWK's inline parameters
        by the selected algorithm.
    :raises InvalidKeyError: If the certificate material, thumbprints, key
        usage or bound public key identity are inconsistent or untrusted.
    """
    if not has_crypto or "x5c" not in jwk_data:
        return

    if not hasattr(public_key, "public_bytes"):
        raise InvalidKeyError(
            "The JWK 'x5c' member can only be attached to an asymmetric key, "
            f"but the JWK key type is {jwk_data.get('kty')!r}"
        )

    certificates = _load_x5c_certificates(jwk_data["x5c"])
    _verify_chain(certificates)

    leaf = certificates[0]
    if _public_key_bytes(leaf.public_key()) != _public_key_bytes(public_key):
        raise InvalidKeyError(
            "The public key in the JWK does not match the public key of the "
            "leaf certificate in 'x5c'"
        )

    _verify_thumbprints(jwk_data, leaf)
    _verify_key_use(jwk_data, leaf)
