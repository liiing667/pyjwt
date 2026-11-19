import base64
import copy
import datetime
import json
from typing import Any, cast

import pytest

import jwt
from cryptography import x509 as x509_module
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from jwt.algorithms import RSAAlgorithm
from jwt.api_jwk import PyJWK, PyJWKSet
from jwt.exceptions import (
    InvalidAlgorithmError,
    InvalidKeyError,
    PyJWKSetError,
)
from jwt.utils import base64url_decode

from .utils import crypto_required, key_path


def _load_fixture(name: str) -> dict[str, Any]:
    with open(key_path(name)) as keyfile:
        return cast(dict[str, Any], json.loads(keyfile.read()))


def _load_private_key(name: str) -> bytes:
    with open(key_path(name), "rb") as keyfile:
        return keyfile.read()


@crypto_required
class TestCertificateChainBinding:
    def test_valid_rsa_chain_binds_single_identity(self) -> None:
        jwk_data = _load_fixture("jwk_x5c_rsa_a.json")
        jwk = PyJWK.from_dict(jwk_data)

        assert jwk.key_type == "RSA"
        assert jwk.algorithm_name == "RS256"
        assert jwk.public_key_use == "sig"
        assert jwk.key_id == jwk_data["kid"]
        assert jwk.key_id == jwk_data["x5t"]

    def test_valid_ec_chain_binds_single_identity(self) -> None:
        jwk_data = _load_fixture("jwk_x5c_ec_d.json")
        jwk = PyJWK.from_dict(jwk_data)

        assert jwk.key_type == "EC"
        assert jwk.algorithm_name == "ES256"
        assert jwk.public_key_use == "sig"

    def test_jwk_verifies_token_signed_by_bound_identity(self) -> None:
        jwk = PyJWK.from_dict(_load_fixture("jwk_x5c_rsa_a.json"))
        private_key = _load_private_key("x5c_rsa_leaf_a_key.pem")

        token = jwt.encode({"sub": "bound-identity"}, private_key, algorithm="RS256")
        decoded = jwt.decode(token, jwk, algorithms=["RS256"])

        assert decoded["sub"] == "bound-identity"

    def test_jwk_rejects_token_signed_by_a_different_identity(self) -> None:
        # The x5c chain and n/e describe leaf A; signing with leaf B's key
        # must not authenticate even though both certs share the same CA.
        jwk = PyJWK.from_dict(_load_fixture("jwk_x5c_rsa_a.json"))
        other_private_key = _load_private_key("x5c_rsa_leaf_b_key.pem")

        token = jwt.encode({"sub": "impostor"}, other_private_key, algorithm="RS256")
        with pytest.raises(jwt.exceptions.InvalidSignatureError):
            jwt.decode(token, jwk, algorithms=["RS256"])

    def test_ec_jwk_verifies_token_signed_by_bound_identity(self) -> None:
        jwk = PyJWK.from_dict(_load_fixture("jwk_x5c_ec_d.json"))
        private_key = _load_private_key("x5c_ec_leaf_d_key.pem")

        token = jwt.encode({"sub": "ec-bound"}, private_key, algorithm="ES256")
        decoded = jwt.decode(token, jwk, algorithms=["ES256"])

        assert decoded["sub"] == "ec-bound"

    def test_rejects_x5c_from_a_different_certificate_identity(self) -> None:
        jwk_a = _load_fixture("jwk_x5c_rsa_a.json")
        jwk_b = _load_fixture("jwk_x5c_rsa_b.json")
        mismatched = copy.deepcopy(jwk_a)
        mismatched["x5c"] = jwk_b["x5c"]

        with pytest.raises(InvalidKeyError, match="public key"):
            PyJWK.from_dict(mismatched)

    def test_rejects_inline_key_parameters_from_a_different_identity(self) -> None:
        jwk_a = _load_fixture("jwk_x5c_rsa_a.json")
        jwk_b = _load_fixture("jwk_x5c_rsa_b.json")
        mismatched = copy.deepcopy(jwk_a)
        mismatched["n"] = jwk_b["n"]
        mismatched["e"] = jwk_b["e"]

        with pytest.raises(InvalidKeyError, match="public key"):
            PyJWK.from_dict(mismatched)

    def test_rejects_malformed_certificate_material(self) -> None:
        jwk_data = _load_fixture("jwk_x5c_rsa_a.json")

        for bad_x5c in (None, [], "not-a-list", [""], [123], ["%%%not-base64"]):
            broken = copy.deepcopy(jwk_data)
            broken["x5c"] = bad_x5c
            with pytest.raises(InvalidKeyError):
                PyJWK.from_dict(broken)

    def test_rejects_unlinked_certificate_chain(self) -> None:
        rsa_jwk = _load_fixture("jwk_x5c_rsa_a.json")
        ec_jwk = _load_fixture("jwk_x5c_ec_d.json")
        broken = copy.deepcopy(rsa_jwk)
        # Leaf A followed by an unrelated CA certificate.
        broken["x5c"] = [rsa_jwk["x5c"][0], ec_jwk["x5c"][1]]

        with pytest.raises(InvalidKeyError, match="not linked"):
            PyJWK.from_dict(broken)

    def test_rejects_tampered_certificate_signature(self) -> None:
        jwk_data = _load_fixture("jwk_x5c_rsa_a.json")
        ca_der = bytearray(base64.b64decode(jwk_data["x5c"][1]))
        # Flip a byte inside the CA signature (the trailing 256 bytes).
        ca_der[-1] ^= 0x01
        broken = copy.deepcopy(jwk_data)
        broken["x5c"][1] = base64.b64encode(bytes(ca_der)).decode("ascii")

        with pytest.raises(InvalidKeyError, match="invalid signature"):
            PyJWK.from_dict(broken)

    def test_rejects_tampered_leaf_certificate_signature(self) -> None:
        jwk_data = _load_fixture("jwk_x5c_rsa_a.json")
        leaf_der = bytearray(base64.b64decode(jwk_data["x5c"][0]))
        leaf_der[-1] ^= 0x01
        broken = copy.deepcopy(jwk_data)
        broken["x5c"][0] = base64.b64encode(bytes(leaf_der)).decode("ascii")

        with pytest.raises(InvalidKeyError, match="invalid signature"):
            PyJWK.from_dict(broken)

    def test_rejects_tampered_self_signed_single_certificate_chain(self) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509_module.Name(
            [x509_module.NameAttribute(NameOID.COMMON_NAME, "self-signed")]
        )
        certificate = (
            x509_module.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(private_key.public_key())
            .serial_number(1)
            .not_valid_before(
                datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
            )
            .not_valid_after(
                datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)
            )
            .sign(private_key, hashes.SHA256())
        )
        jwk_data = json.loads(
            RSAAlgorithm(RSAAlgorithm.SHA256).to_jwk(private_key.public_key())
        )
        jwk_data["alg"] = "RS256"
        jwk_data["x5c"] = [
            base64.b64encode(
                certificate.public_bytes(serialization.Encoding.DER)
            ).decode("ascii")
        ]
        assert PyJWK.from_dict(jwk_data).algorithm_name == "RS256"

        der = bytearray(base64.b64decode(jwk_data["x5c"][0]))
        der[-1] ^= 0x01
        jwk_data["x5c"][0] = base64.b64encode(bytes(der)).decode("ascii")

        with pytest.raises(InvalidKeyError, match="invalid signature"):
            PyJWK.from_dict(jwk_data)

    def test_rejects_wrong_x5t_thumbprint(self) -> None:
        jwk_a = _load_fixture("jwk_x5c_rsa_a.json")
        jwk_b = _load_fixture("jwk_x5c_rsa_b.json")
        broken = copy.deepcopy(jwk_a)
        broken["x5t"] = jwk_b["x5t"]

        with pytest.raises(InvalidKeyError, match="x5t"):
            PyJWK.from_dict(broken)

    def test_rejects_wrong_x5t_s256_thumbprint(self) -> None:
        jwk_a = _load_fixture("jwk_x5c_rsa_a.json")
        jwk_b = _load_fixture("jwk_x5c_rsa_b.json")
        broken = copy.deepcopy(jwk_a)
        broken["x5t#S256"] = jwk_b["x5t#S256"]

        with pytest.raises(InvalidKeyError, match="x5t#S256"):
            PyJWK.from_dict(broken)

    def test_rejects_kid_thumbprint_conflict_when_kid_equals_x5t(self) -> None:
        jwk_a = _load_fixture("jwk_x5c_rsa_a.json")
        jwk_b = _load_fixture("jwk_x5c_rsa_b.json")
        broken = copy.deepcopy(jwk_a)
        # The JWK asserts kid is its thumbprint by copying x5t, but the value
        # belongs to a different certificate.
        broken["x5t"] = jwk_b["x5t"]
        broken["kid"] = jwk_b["x5t"]

        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(broken)

    def test_accepts_opaque_kid_unrelated_to_thumbprints(self) -> None:
        jwk_data = _load_fixture("jwk_x5c_rsa_a.json")
        jwk_data["kid"] = "opaque-key-id-not-a-thumbprint"

        jwk = PyJWK.from_dict(jwk_data)
        assert jwk.key_id == "opaque-key-id-not-a-thumbprint"

    def test_rejects_sig_use_on_encipherment_only_certificate(self) -> None:
        enc_jwk = _load_fixture("jwk_x5c_rsa_enc.json")
        broken = copy.deepcopy(enc_jwk)
        broken["use"] = "sig"

        with pytest.raises(InvalidKeyError, match="use"):
            PyJWK.from_dict(broken)

    def test_rejects_enc_use_on_signature_only_certificate(self) -> None:
        sig_jwk = _load_fixture("jwk_x5c_rsa_a.json")
        broken = copy.deepcopy(sig_jwk)
        broken["use"] = "enc"

        with pytest.raises(InvalidKeyError, match="use"):
            PyJWK.from_dict(broken)

    def test_accepts_enc_jwk_bound_to_encipherment_certificate(self) -> None:
        jwk = PyJWK.from_dict(_load_fixture("jwk_x5c_rsa_enc.json"))
        assert jwk.public_key_use == "enc"

    def test_algorithm_conflict_with_key_type_fails_closed(self) -> None:
        jwk_data = _load_fixture("jwk_x5c_rsa_a.json")
        jwk_data["alg"] = "ES256"

        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(jwk_data)

    def test_token_algorithm_mismatch_against_bound_alg_fails_closed(self) -> None:
        jwk = PyJWK.from_dict(_load_fixture("jwk_x5c_rsa_a.json"))
        private_key = _load_private_key("x5c_rsa_leaf_a_key.pem")
        token = jwt.encode({"sub": "ok"}, private_key, algorithm="RS256")

        with pytest.raises(InvalidAlgorithmError):
            jwt.decode(token, jwk, algorithms=["ES256"])

    def test_multi_algorithm_rotation_set_still_loads(self) -> None:
        rsa_jwk = _load_fixture("jwk_x5c_rsa_a.json")
        ec_jwk = _load_fixture("jwk_x5c_ec_d.json")

        key_set = PyJWKSet.from_dict({"keys": [rsa_jwk, ec_jwk]})

        assert {key.algorithm_name for key in key_set} == {"RS256", "ES256"}
        assert key_set[rsa_jwk["kid"]].key_type == "RSA"
        assert key_set[ec_jwk["kid"]].key_type == "EC"

    def test_rotation_set_skips_conflicting_key_but_keeps_valid_chain(self) -> None:
        good = _load_fixture("jwk_x5c_rsa_a.json")
        evil = _load_fixture("jwk_x5c_rsa_b.json")
        evil["n"] = good["n"]
        evil["e"] = good["e"]

        key_set = PyJWKSet.from_dict({"keys": [evil, good]})

        assert len(key_set.keys) == 1
        assert key_set.keys[0].key_id == good["kid"]

    def test_keyset_of_only_conflicting_chains_raises_set_error(self) -> None:
        good = _load_fixture("jwk_x5c_rsa_a.json")
        evil = _load_fixture("jwk_x5c_rsa_b.json")
        evil["n"] = good["n"]
        evil["e"] = good["e"]

        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_dict({"keys": [evil]})

    def test_legacy_hex_ascii_x5t_encoding_is_accepted(self) -> None:
        # Auth0-style JWKs encode the uppercase hex SHA-1 digest as ASCII and
        # then base64url-encode those 40 bytes.
        jwk_data = _load_fixture("jwk_x5c_rsa_a.json")
        sha1_hex = base64url_decode(jwk_data["x5t"]).hex().upper().encode("ascii")
        jwk_data["x5t"] = (
            base64.urlsafe_b64encode(sha1_hex).rstrip(b"=").decode("ascii")
        )

        jwk = PyJWK.from_dict(jwk_data)
        assert jwk.key_id is not None

    def test_jwk_without_x5c_is_unaffected(self) -> None:
        jwk_data = _load_fixture("jwk_x5c_rsa_a.json")
        del jwk_data["x5c"]
        del jwk_data["x5t"]
        del jwk_data["x5t#S256"]

        jwk = PyJWK.from_dict(jwk_data)
        assert jwk.key_type == "RSA"

    def test_symmetric_jwk_carrying_x5c_fails_closed(self) -> None:
        rsa_jwk = _load_fixture("jwk_x5c_rsa_a.json")
        symmetric = {
            "kty": "oct",
            "alg": "HS256",
            "k": "c2VjcmV0c2VjcmV0c2VjcmV0c2VjcmV0",
            "x5c": rsa_jwk["x5c"],
        }

        with pytest.raises(InvalidKeyError, match="asymmetric"):
            PyJWK.from_dict(symmetric)
