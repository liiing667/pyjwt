"""Validation for the certificate members of a JSON Web Key.

A JWK may carry an ``x5c`` certificate chain alongside the raw public key
members (e.g. RSA ``n``/``e`` or EC ``crv``/``x``/``y``) as well as ``x5t``
and ``x5t#S256`` thumbprints. Each of those members is unkeyed metadata: on
its own nothing proves that it describes the same public-key identity as the
rest of the JWK.

The helpers in this module bind those members to a single verifiable
identity. Every inconsistency fails closed with
:class:`~jwt.exceptions.InvalidCertificateError` instead of silently letting
an application trust certificate material that does not match the key used
for signature verification.
"""

from __future__ import annotations

import base64
import binascii
from typing import TYPE_CHECKING, Any

from .exceptions import InvalidCertificateError
from .types import JWKDict
from .utils import force_bytes

try:
    from cryptography import x509
    from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )
    from cryptography.x509 import Certificate

    has_crypto = True
except ModuleNotFoundError:  # pragma: no cover
    has_crypto = False

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.types import PublicKeyTypes


def _decode_strict_base64(value: Any, *, urlsafe: bool, member: str) -> bytes:
    if not isinstance(value, str):
        raise InvalidCertificateError(
            f"JWK {member} member must be a base64-encoded string"
        )

    encoded = force_bytes(value)
    encoded = b"".join(encoded.split())
    padded = encoded + b"=" * (-len(encoded) % 4)
    alphabet = b"-_" if urlsafe else b"+/"
    try:
        return base64.b64decode(padded, altchars=alphabet, validate=True)
    except (binascii.Error, ValueError) as error:
        raise InvalidCertificateError(
            f"JWK {member} member is not valid base64 data"
        ) from error


def load_x5c_chain(x5c: Any) -> list[Certificate]:
    """Parse the ``x5c`` member into DER certificates.

    :raises InvalidCertificateError: If ``x5c`` is not a non-empty list of
        base64-encoded DER certificates or if any element cannot be parsed.
    """
    if not isinstance(x5c, list) or not x5c:
        raise InvalidCertificateError(
            "JWK x5c member must be a non-empty list of certificates"
        )

    chain: list[Certificate] = []
    for index, entry in enumerate(x5c):
        der = _decode_strict_base64(entry, urlsafe=False, member="x5c")
        try:
            chain.append(x509.load_der_x509_certificate(der))
        except ValueError as error:
            raise InvalidCertificateError(
                f"JWK x5c entry {index} is not a valid DER certificate"
            ) from error

    return chain


def _same_public_key(left: Any, right: Any) -> bool:
    return bool(
        left.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        == right.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    )


def _verify_certificate_signature(certificate: Any, issuer_public_key: Any) -> None:
    hash_algorithm = certificate.signature_hash_algorithm
    try:
        if isinstance(issuer_public_key, rsa.RSAPublicKey):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                hash_algorithm,
            )
        elif isinstance(issuer_public_key, ec.EllipticCurvePublicKey):
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(hash_algorithm),
            )
        else:
            # Ed25519/Ed448 certificates are signed without a separate hash.
            issuer_public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
            )
    except (InvalidSignature, UnsupportedAlgorithm, TypeError) as error:
        raise InvalidCertificateError(
            "JWK x5c chain contains a certificate whose signature does not "
            "verify against its issuer"
        ) from error


def _verify_chain(chain: list[Certificate]) -> None:
    for index, certificate in enumerate(chain):
        issuer = chain[index + 1] if index + 1 < len(chain) else certificate

        if certificate.issuer != issuer.subject:
            raise InvalidCertificateError(
                "JWK x5c chain is not contiguous: certificate "
                f"{index} was not issued by the next certificate in the chain"
            )

        _verify_certificate_signature(certificate, issuer.public_key())


def _verify_thumbprint(
    jwk_data: JWKDict,
    member: str,
    leaf_certificate: Certificate,
    hash_algorithm: Any,
) -> None:
    if member not in jwk_data:
        return

    expected = _decode_strict_base64(jwk_data[member], urlsafe=True, member=member)
    actual = leaf_certificate.fingerprint(hash_algorithm)
    if expected != actual:
        raise InvalidCertificateError(
            f"JWK {member} thumbprint does not match the leaf certificate "
            "in the x5c chain"
        )


def verify_certificate_binding(
    jwk_data: JWKDict, public_key: PublicKeyTypes
) -> list[Certificate]:
    """Bind every certificate-related JWK member to one public key.

    Confirms that the leaf certificate in ``x5c`` carries ``public_key``,
    that the chain is contiguous and internally signed, and that any
    ``x5t`` / ``x5t#S256`` thumbprints describe the leaf certificate.

    :raises InvalidCertificateError: On any mismatch or malformed material.
    :returns: The parsed, validated certificate chain (empty without x5c).
    """
    for member in ("x5t", "x5t#S256"):
        if member in jwk_data and "x5c" not in jwk_data:
            raise InvalidCertificateError(
                f"JWK {member} member cannot be verified without an x5c "
                "certificate chain"
            )

    if "x5c" not in jwk_data:
        return []

    if not has_crypto:  # pragma: no cover
        raise InvalidCertificateError(
            "Validating an x5c certificate chain requires 'cryptography' "
            "to be installed."
        )

    if not hasattr(public_key, "public_bytes"):
        raise InvalidCertificateError(
            "JWK x5c certificate chains can only be combined with an "
            "asymmetric public key"
        )

    chain = load_x5c_chain(jwk_data["x5c"])
    leaf = chain[0]

    if not _same_public_key(leaf.public_key(), public_key):
        raise InvalidCertificateError(
            "The public key in the JWK x5c leaf certificate does not match "
            "the key represented by the JWK's other key members"
        )

    _verify_chain(chain)

    _verify_thumbprint(jwk_data, "x5t", leaf, hashes.SHA1())
    _verify_thumbprint(jwk_data, "x5t#S256", leaf, hashes.SHA256())

    return chain


def validate_key_use(
    jwk_data: JWKDict, leaf_certificate: Certificate | None, algorithm_name: str
) -> None:
    """Validate the JWK ``use`` member against algorithm and certificate.

    PyJWK only constructs signature and MAC keys, so an ``enc`` key can never
    be used safely here. When the leaf certificate carries a key usage
    extension, the declared use must also be permitted by that extension.

    :raises InvalidCertificateError: On any conflicting or unknown use.
    """
    use = jwk_data.get("use")
    if use is None:
        return

    if use not in ("sig", "enc"):
        raise InvalidCertificateError(
            f"JWK use member {use!r} is not a recognized key use"
        )

    if use == "enc":
        raise InvalidCertificateError(
            f"JWK declares use 'enc' but algorithm {algorithm_name!r} is a "
            "signature algorithm; the key cannot be used for verification"
        )

    if leaf_certificate is None:
        return

    try:
        key_usage = leaf_certificate.extensions.get_extension_for_class(
            x509.KeyUsage
        ).value
    except x509.ExtensionNotFound:
        return

    if not key_usage.digital_signature:
        raise InvalidCertificateError(
            "JWK declares use 'sig' but the x5c leaf certificate's key usage "
            "extension does not permit digital signatures"
        )
