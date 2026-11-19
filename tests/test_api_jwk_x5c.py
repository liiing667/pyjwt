"""Certificate-chain binding tests for :class:`jwt.PyJWK`.

These tests pin the security model for JWKs that carry ``x5c`` / ``x5t``
members: the whole JWK must resolve to a single verifiable public-key
identity. Certificate material, thumbprints, key use and algorithm
conflicts fail closed, while a legitimate chain and multi-algorithm key
rotation continue to verify real signatures.
"""

from __future__ import annotations

import base64
import copy
import json

import pytest

import jwt
from jwt.algorithms import has_crypto
from jwt.api_jwk import PyJWK, PyJWKSet
from jwt.exceptions import (
    InvalidAlgorithmError,
    InvalidCertificateError,
    InvalidKeyError,
    PyJWKSetError,
)
from jwt.types import JWKDict

from .utils import crypto_required, key_path

if has_crypto:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )


def _load(name: str) -> JWKDict:
    with open(key_path(name)) as handle:
        data: JWKDict = json.load(handle)
        return data


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


@crypto_required
class TestCertificateChainBinding:
    @pytest.fixture(params=["jwk_x5c_alpha_rsa.json", "jwk_x5c_alpha_ec.json"])
    def jwk_data(self, request: pytest.FixtureRequest) -> JWKDict:
        return _load(request.param)

    def test_legitimate_chain_binds_one_identity(self, jwk_data: JWKDict) -> None:
        jwk = PyJWK(jwk_data)

        assert len(jwk.certificates) == 2
        leaf, root = jwk.certificates
        assert jwk.certificate is leaf
        assert leaf.issuer == root.subject
        assert leaf.subject.rfc4514_string() == "CN=jwk-alpha.example"

        # The verification key and the certificate's public key are the same
        # DER-encoded identity.
        assert jwk.key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        ) == leaf.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )

    def test_signature_verifies_against_bound_identity(self, jwk_data: JWKDict) -> None:
        suffix = "rsa" if jwk_data["kty"] == "RSA" else "ec"
        with open(key_path(f"jwk_x5c_alpha_{suffix}.priv.pem"), "rb") as handle:
            private_key = handle.read()

        token = jwt.encode(
            {"sub": "alpha", "event": "bound"},
            private_key,
            algorithm=jwk_data["alg"],
            headers={"kid": jwk_data["kid"]},
        )

        jwk = PyJWK(jwk_data)
        decoded = jwt.decode(token, jwk.key, algorithms=[jwk.algorithm_name])
        assert decoded["sub"] == "alpha"

        # A token from a different identity must not verify with this key.
        other = _load(f"jwk_x5c_bravo_{suffix}.json")
        with open(key_path(f"jwk_x5c_bravo_{suffix}.priv.pem"), "rb") as handle:
            other_private = handle.read()
        foreign_token = jwt.encode(
            {"sub": "bravo"}, other_private, algorithm=other["alg"]
        )
        with pytest.raises(jwt.InvalidSignatureError):
            jwt.decode(foreign_token, jwk.key, algorithms=[jwk.algorithm_name])

    def test_identities_are_distinct_across_chains(self) -> None:
        alpha = PyJWK(_load("jwk_x5c_alpha_rsa.json"))
        bravo = PyJWK(_load("jwk_x5c_bravo_rsa.json"))

        assert alpha.key_id != bravo.key_id
        assert alpha.certificate.subject != bravo.certificate.subject
        assert alpha.certificate.fingerprint(
            hashes.SHA1()
        ) != bravo.certificate.fingerprint(hashes.SHA1())
        assert alpha.key.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        ) != bravo.key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def test_multi_algorithm_rotation_inside_one_keyset(self) -> None:
        rsa_key = _load("jwk_x5c_alpha_rsa.json")
        ec_key = _load("jwk_x5c_alpha_ec.json")
        key_set = PyJWKSet.from_dict({"keys": [rsa_key, ec_key]})

        assert {key.algorithm_name for key in key_set} == {"RS256", "ES256"}
        assert key_set["alpha-rsa-1"].certificate.subject.rfc4514_string() == (
            "CN=jwk-alpha.example"
        )
        assert key_set["alpha-ec-1"].certificate.subject.rfc4514_string() == (
            "CN=jwk-alpha.example"
        )

        with open(key_path("jwk_x5c_alpha_rsa.priv.pem"), "rb") as handle:
            rsa_private = handle.read()
        with open(key_path("jwk_x5c_alpha_ec.priv.pem"), "rb") as handle:
            ec_private = handle.read()

        rotated = [
            jwt.encode(
                {"sub": "rotation"},
                private,
                algorithm=key["alg"],
                headers={"kid": key["kid"]},
            )
            for key, private in (
                (rsa_key, rsa_private),
                (ec_key, ec_private),
            )
        ]

        for token in rotated:
            header = jwt.get_unverified_header(token)
            signing_key = key_set[header["kid"]]
            assert jwt.decode(
                token, signing_key.key, algorithms=["RS256", "ES256"]
            ) == {"sub": "rotation"}

    def test_jwk_without_certificate_members_is_unaffected(self) -> None:
        jwk = PyJWK(_load("jwk_rsa_pub.json"))
        assert jwk.certificates == []
        assert jwk.certificate is None


@crypto_required
class TestCertificateConflictsFailClosed:
    def test_n_e_from_another_certificate_is_rejected(self) -> None:
        alpha = _load("jwk_x5c_alpha_rsa.json")
        bravo = _load("jwk_x5c_bravo_rsa.json")
        tampered = copy.deepcopy(alpha)
        tampered["n"] = bravo["n"]

        with pytest.raises(InvalidCertificateError) as exc:
            PyJWK(tampered)
        assert "does not match" in str(exc.value)

    def test_x5c_from_another_identity_is_rejected(self) -> None:
        alpha = _load("jwk_x5c_alpha_rsa.json")
        bravo = _load("jwk_x5c_bravo_rsa.json")
        tampered = copy.deepcopy(alpha)
        tampered["x5c"] = bravo["x5c"]

        with pytest.raises(InvalidCertificateError):
            PyJWK(tampered)

    def test_swapped_leaf_and_root_breaks_chain(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data["x5c"] = list(reversed(jwk_data["x5c"]))

        with pytest.raises(InvalidCertificateError):
            PyJWK(jwk_data)

    def test_unrelated_root_is_rejected(self) -> None:
        alpha = _load("jwk_x5c_alpha_rsa.json")
        bravo = _load("jwk_x5c_bravo_rsa.json")
        tampered = copy.deepcopy(alpha)
        tampered["x5c"] = [alpha["x5c"][0], bravo["x5c"][1]]

        with pytest.raises(InvalidCertificateError):
            PyJWK(tampered)

    def test_tampered_leaf_signature_is_rejected(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        leaf_der = bytearray(base64.b64decode(jwk_data["x5c"][0]))
        leaf_der[-1] ^= 0x01
        jwk_data["x5c"][0] = base64.b64encode(bytes(leaf_der)).decode("ascii")

        with pytest.raises(InvalidCertificateError):
            PyJWK(jwk_data)

    @pytest.mark.parametrize("member", ["x5t", "x5t#S256"])
    def test_wrong_thumbprint_is_rejected(self, member: str) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data[member] = _b64url(b"not-the-real-thumbprint-here!!")

        with pytest.raises(InvalidCertificateError) as exc:
            PyJWK(jwk_data)
        assert member in str(exc.value)

    @pytest.mark.parametrize("member", ["x5t", "x5t#S256"])
    def test_malformed_thumbprint_is_rejected(self, member: str) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data[member] = "not base64!!"

        with pytest.raises(InvalidCertificateError):
            PyJWK(jwk_data)

    def test_malformed_x5c_entry_is_rejected(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data["x5c"][0] = "not-a-certificate"

        with pytest.raises(InvalidCertificateError):
            PyJWK(jwk_data)

    def test_non_string_x5c_entry_is_rejected(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data["x5c"][0] = 12345

        with pytest.raises(InvalidCertificateError):
            PyJWK(jwk_data)

    def test_x5c_on_symmetric_key_is_rejected(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        symmetric = {
            "kty": "oct",
            "alg": "HS256",
            "k": _b64url(b"a-symmetric-secret-long-enough-to-sign"),
            "x5c": jwk_data["x5c"],
        }

        with pytest.raises(InvalidCertificateError):
            PyJWK(symmetric)

    def test_empty_x5c_is_rejected(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data["x5c"] = []

        with pytest.raises(InvalidCertificateError):
            PyJWK(jwk_data)

    @pytest.mark.parametrize("member", ["x5t", "x5t#S256"])
    def test_thumbprint_without_x5c_is_rejected(self, member: str) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data.pop("x5c")
        jwk_data = {
            key: value
            for key, value in jwk_data.items()
            if key == member or not key.startswith("x5t")
        }

        with pytest.raises(InvalidCertificateError) as exc:
            PyJWK(jwk_data)
        assert member in str(exc.value)

    def test_use_enc_with_signature_algorithm_is_rejected(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data["use"] = "enc"

        with pytest.raises(InvalidCertificateError) as exc:
            PyJWK(jwk_data)
        assert "enc" in str(exc.value)

    def test_unknown_use_is_rejected(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk_data["use"] = "sig+enc"

        with pytest.raises(InvalidCertificateError):
            PyJWK(jwk_data)

    def test_certificate_key_usage_conflict_is_rejected(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa_keyencipherment.json")

        with pytest.raises(InvalidCertificateError) as exc:
            PyJWK(jwk_data)
        assert "digital signatures" in str(exc.value)

    def test_algorithm_argument_conflicts_with_jwk_alg(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")

        with pytest.raises(InvalidAlgorithmError):
            PyJWK(jwk_data, algorithm="RS384")

    def test_algorithm_argument_matching_jwk_alg_is_accepted(self) -> None:
        jwk_data = _load("jwk_x5c_alpha_rsa.json")
        jwk = PyJWK(jwk_data, algorithm="RS256")
        assert jwk.algorithm_name == "RS256"

    def test_keyset_skips_conflicting_key_but_keeps_legitimate_one(self) -> None:
        tampered = _load("jwk_x5c_alpha_rsa.json")
        tampered["x5t"] = _b64url(b"wrong-thumbprint-here-padding-xx")
        valid = _load("jwk_x5c_bravo_rsa.json")

        key_set = PyJWKSet.from_dict({"keys": [tampered, valid]})

        assert [key.key_id for key in key_set.keys] == ["bravo-rsa-1"]

    def test_keyset_with_only_conflicting_keys_fails_closed(self) -> None:
        tampered = _load("jwk_x5c_alpha_rsa.json")
        tampered["n"] = _load("jwk_x5c_bravo_rsa.json")["n"]

        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_dict({"keys": [tampered]})


@crypto_required
def test_invalid_certificate_error_is_an_invalid_key_error() -> None:
    assert issubclass(InvalidCertificateError, InvalidKeyError)
