"""Regenerate the fixed x5c JWK fixtures used by the certificate tests.

The generated key material is random on every run and intended for tests
only. The fixtures model two distinct verifiable identities ("alpha" and
"bravo"), each with its own root certificate authority, an RSA signing key
and an EC signing key, so the tests can demonstrate signature verification,
identity separation and multi-algorithm rotation over certificate chains.
"""

from __future__ import annotations

import base64
import datetime
import json
import os
from typing import Any, cast

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509.oid import NameOID


HERE = os.path.dirname(os.path.abspath(__file__))
NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2046, 1, 1, tzinfo=datetime.timezone.utc)


def b64url_der(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64_der(value: bytes) -> str:
    return base64.encodebytes(value).decode("ascii").replace("\n", "")


def write_json(name: str, payload: dict[str, Any]) -> None:
    with open(os.path.join(HERE, name), "w") as handle:
        json.dump(payload, handle, indent=2)
        handle.write("\n")


def write_pem(name: str, private_key: PrivateKeyTypes) -> None:
    path = os.path.join(HERE, name)
    with open(path, "wb") as handle:
        handle.write(
            private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


def root_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    rng = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(rng.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(rng, hashes.SHA256())
    )
    return rng, certificate


def issue_leaf(
    *,
    identity: str,
    ca_key: rsa.RSAPrivateKey,
    ca_cert: x509.Certificate,
    private_key: PrivateKeyTypes,
    sign_usage: bool,
) -> x509.Certificate:
    subject = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, f"jwk-{identity}.example")]
    )
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(cast(Any, private_key).public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=sign_usage,
                content_commitment=False,
                key_encipherment=not sign_usage,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )


def rsa_jwk(private_key: rsa.RSAPrivateKey) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "n": b64url_der(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")),
        "e": b64url_der(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")),
    }


def ec_jwk(private_key: ec.EllipticCurvePrivateKey) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()
    size = (private_key.curve.key_size + 7) // 8
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_der(numbers.x.to_bytes(size, "big")),
        "y": b64url_der(numbers.y.to_bytes(size, "big")),
    }


def chain_x5c(leaf: x509.Certificate, root: x509.Certificate) -> list[str]:
    return [
        b64_der(leaf.public_bytes(serialization.Encoding.DER)),
        b64_der(root.public_bytes(serialization.Encoding.DER)),
    ]


def main() -> None:
    for identity in ("alpha", "bravo"):
        ca_key, ca_cert = root_ca(f"jwk-test-root-{identity}")

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rsa_leaf = issue_leaf(
            identity=identity,
            ca_key=ca_key,
            ca_cert=ca_cert,
            private_key=rsa_key,
            sign_usage=True,
        )

        rsa_payload = rsa_jwk(rsa_key)
        rsa_payload.update(
            {
                "alg": "RS256",
                "use": "sig",
                "kid": f"{identity}-rsa-1",
                "x5c": chain_x5c(rsa_leaf, ca_cert),
                "x5t": b64url_der(rsa_leaf.fingerprint(hashes.SHA1())),
                "x5t#S256": b64url_der(rsa_leaf.fingerprint(hashes.SHA256())),
            }
        )

        write_json(f"jwk_x5c_{identity}_rsa.json", rsa_payload)
        write_pem(f"jwk_x5c_{identity}_rsa.priv.pem", rsa_key)

        # Both identities carry an EC key so tests can compare foreign
        # signatures across EC chains; alpha additionally uses it for the
        # multi-algorithm rotation coverage.
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_leaf = issue_leaf(
            identity=identity,
            ca_key=ca_key,
            ca_cert=ca_cert,
            private_key=ec_key,
            sign_usage=True,
        )
        ec_payload = ec_jwk(ec_key)
        ec_payload.update(
            {
                "alg": "ES256",
                "use": "sig",
                "kid": f"{identity}-ec-1",
                "x5c": chain_x5c(ec_leaf, ca_cert),
                "x5t": b64url_der(ec_leaf.fingerprint(hashes.SHA1())),
                "x5t#S256": b64url_der(ec_leaf.fingerprint(hashes.SHA256())),
            }
        )
        write_json(f"jwk_x5c_{identity}_ec.json", ec_payload)
        write_pem(f"jwk_x5c_{identity}_ec.priv.pem", ec_key)

        if identity != "alpha":
            continue

        # A leaf whose certificate forbids digital signatures exercises the
        # use/key-usage conflict path without hand-editing DER bytes.
        enc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        enc_leaf = issue_leaf(
            identity=identity,
            ca_key=ca_key,
            ca_cert=ca_cert,
            private_key=enc_key,
            sign_usage=False,
        )
        enc_payload = rsa_jwk(enc_key)
        enc_payload.update(
            {
                "alg": "RS256",
                "use": "sig",
                "kid": f"{identity}-rsa-enc",
                "x5c": chain_x5c(enc_leaf, ca_cert),
                "x5t": b64url_der(enc_leaf.fingerprint(hashes.SHA1())),
                "x5t#S256": b64url_der(enc_leaf.fingerprint(hashes.SHA256())),
            }
        )
        write_json(f"jwk_x5c_{identity}_rsa_keyencipherment.json", enc_payload)


if __name__ == "__main__":
    main()
