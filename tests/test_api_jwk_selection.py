"""Matrix coverage for same-``kid`` JWK Set member selection.

A JWK Set can contain several members carrying the same ``kid``: a private
key and its public counterpart, a plain public key and a certificate-backed
representation, or keys of different types and algorithms. Selection must be
decided by set membership, key type, algorithm and use together, fail closed
on genuine ambiguity, and keep legitimate rotation (unique kids / unique
identities) working.
"""

import json
from typing import Any, cast

import pytest

from jwt.api_jwk import PyJWK, PyJWKSet
from jwt.exceptions import PyJWKSetAmbiguousKeyError, PyJWKSetError

from .utils import crypto_required, key_path


def _load_jwk(name: str) -> dict[str, Any]:
    with open(key_path(name)) as keyfile:
        return cast(dict[str, Any], json.load(keyfile))


@pytest.fixture
def rsa_private() -> dict[str, Any]:
    return _load_jwk("jwk_rsa_key.json")


@pytest.fixture
def rsa_public() -> dict[str, Any]:
    return _load_jwk("jwk_rsa_pub.json")


@pytest.fixture
def ec_private() -> dict[str, Any]:
    return _load_jwk("jwk_ec_key_P-256.json")


@pytest.fixture
def ec_public() -> dict[str, Any]:
    return _load_jwk("jwk_ec_pub_P-256.json")


@pytest.fixture
def hmac_key() -> dict[str, Any]:
    return _load_jwk("jwk_hmac.json")


@crypto_required
class TestPyJWKMaterialClassification:
    def test_private_public_symmetric_and_certificate_are_distinguished(
        self,
        rsa_private: dict[str, Any],
        rsa_public: dict[str, Any],
        hmac_key: dict[str, Any],
    ) -> None:
        assert PyJWK(rsa_private).key_material == "private"
        assert PyJWK(rsa_private).has_private_key is True

        assert PyJWK(rsa_public).key_material == "public"
        assert PyJWK(rsa_public).has_private_key is False

        assert PyJWK(hmac_key).key_material == "symmetric"
        assert PyJWK(hmac_key).is_symmetric is True
        # A symmetric secret is not treated as an asymmetric private key.
        assert PyJWK(hmac_key).has_private_key is False

        certificate_key = dict(rsa_public, x5c=["MIIB"], x5t="thumbprint")
        assert PyJWK(certificate_key).key_material == "certificate"
        assert PyJWK(certificate_key).has_certificate is True
        assert PyJWK(rsa_public).has_certificate is False


@crypto_required
class TestPyJWKSetSelectionMatrix:
    def test_private_and_public_sharing_kid_resolves_to_public(
        self, rsa_private: dict[str, Any], rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        key_set = PyJWKSet(
            [dict(rsa_private, alg="RS256"), dict(rsa_public, alg="RS256")]
        )

        chosen = key_set.get_key(kid, algorithm="RS256")

        assert chosen.key_material == "public"
        assert chosen.has_private_key is False

    def test_private_only_set_fails_closed_for_verification(
        self, rsa_private: dict[str, Any]
    ) -> None:
        kid = rsa_private["kid"]
        key_set = PyJWKSet([dict(rsa_private, alg="RS256")])

        with pytest.raises(PyJWKSetAmbiguousKeyError):
            key_set.get_key(kid, algorithm="RS256")

    def test_ec_private_and_public_sharing_kid_resolves_to_public(
        self, ec_private: dict[str, Any], ec_public: dict[str, Any]
    ) -> None:
        kid = ec_public["kid"]
        key_set = PyJWKSet(
            [dict(ec_private, alg="ES256"), dict(ec_public, alg="ES256")]
        )

        chosen = key_set.get_key(kid, algorithm="ES256")

        assert chosen.key_material == "public"
        assert chosen.key_type == "EC"

    def test_distinct_public_key_types_sharing_kid_are_ambiguous_without_alg(
        self, rsa_public: dict[str, Any], ec_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        key_set = PyJWKSet(
            [
                dict(rsa_public, alg="RS256"),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        )

        with pytest.raises(PyJWKSetAmbiguousKeyError):
            key_set.get_key(kid)

    @pytest.mark.parametrize(
        ("algorithm", "expected_kty"),
        [("RS256", "RSA"), ("ES256", "EC")],
    )
    def test_algorithm_disambiguates_same_kid_key_types(
        self,
        rsa_public: dict[str, Any],
        ec_public: dict[str, Any],
        algorithm: str,
        expected_kty: str,
    ) -> None:
        kid = rsa_public["kid"]
        key_set = PyJWKSet(
            [
                dict(rsa_public, alg="RS256"),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        )

        chosen = key_set.get_key(kid, algorithm=algorithm)

        assert chosen.key_type == expected_kty
        assert chosen.algorithm_name == algorithm

    def test_explicit_alg_conflict_rejects_the_member(
        self, rsa_public: dict[str, Any], ec_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        key_set = PyJWKSet(
            [
                # No explicit alg: any RSA-family algorithm may use it.
                dict(rsa_public),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        )

        # The EC member explicitly declares ES256, so it is rejected for an
        # RSA-family request and the unrestricted RSA member is selected.
        chosen = key_set.get_key(kid, algorithm="RS384")
        assert chosen.key_type == "RSA"

        # ES384 conflicts with the EC member's explicit ES256 declaration,
        # and the RSA family cannot perform an EC algorithm at all, so no
        # member survives the filters.
        with pytest.raises(PyJWKSetAmbiguousKeyError):
            key_set.get_key(kid, algorithm="ES384")

    def test_explicit_alg_member_is_rejected_for_other_algorithm(
        self, rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        key_set = PyJWKSet([dict(rsa_public, alg="RS256")])

        assert key_set.get_key(kid, algorithm="RS256").key_type == "RSA"
        with pytest.raises(PyJWKSetAmbiguousKeyError):
            key_set.get_key(kid, algorithm="RS384")

    def test_use_member_partitions_same_kid_members(
        self, rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        encryption_key = dict(rsa_public, kid=kid, use="enc", alg="RS256")
        signing_key = dict(rsa_public, kid="sig-copy", use="sig", alg="RS256")
        key_set = PyJWKSet([encryption_key, signing_key])

        with pytest.raises(PyJWKSetAmbiguousKeyError):
            key_set.get_key(kid, use="sig")

        # The enc member is reachable only by callers explicitly asking for
        # that use; signature verification never selects it.
        chosen = key_set.get_key(kid, use="enc")
        assert chosen.public_key_use == "enc"

    def test_certificate_and_plain_public_key_are_distinct_members(
        self, rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        plain = dict(rsa_public, alg="RS256")
        certificate = dict(rsa_public, alg="RS256", x5c=["MIIB"], x5t="t")
        key_set = PyJWKSet([plain, certificate])

        with pytest.raises(PyJWKSetAmbiguousKeyError):
            key_set.get_key(kid, algorithm="RS256")

    def test_duplicate_identical_member_is_not_ambiguous(
        self, rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        member = dict(rsa_public, alg="RS256")
        key_set = PyJWKSet([dict(member), dict(member)])

        chosen = key_set.get_key(kid, algorithm="RS256")
        assert chosen.key_id == kid

    def test_legitimate_rotation_with_distinct_kids_keeps_both_keys(
        self, rsa_public: dict[str, Any]
    ) -> None:
        old_key = dict(rsa_public, kid="rotation-old", alg="RS256")
        new_key = dict(rsa_public, kid="rotation-new", alg="RS256")
        key_set = PyJWKSet([old_key, new_key])

        assert key_set.get_key("rotation-old", algorithm="RS256").key_id == (
            "rotation-old"
        )
        assert key_set.get_key("rotation-new", algorithm="RS256").key_id == (
            "rotation-new"
        )

    def test_unknown_kid_raises_set_error(self, rsa_public: dict[str, Any]) -> None:
        key_set = PyJWKSet([dict(rsa_public, alg="RS256")])

        with pytest.raises(PyJWKSetAmbiguousKeyError):
            key_set.get_key("missing-kid", algorithm="RS256")

    def test_getitem_mapping_protocol_still_indexes_by_kid(
        self, rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        key_set = PyJWKSet([dict(rsa_public, alg="RS256")])

        assert key_set[kid].key_id == kid
        with pytest.raises(KeyError):
            _ = key_set["missing-kid"]

    def test_getitem_raises_key_error_on_ambiguous_kid(
        self, rsa_public: dict[str, Any], ec_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        key_set = PyJWKSet(
            [
                dict(rsa_public, alg="RS256"),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        )

        with pytest.raises(KeyError):
            _ = key_set[kid]

    def test_symmetric_and_asymmetric_same_kid_are_disambiguated_by_algorithm(
        self, rsa_public: dict[str, Any], hmac_key: dict[str, Any]
    ) -> None:
        kid = "shared-kid"
        key_set = PyJWKSet(
            [
                dict(rsa_public, kid=kid, alg="RS256"),
                dict(hmac_key, kid=kid),
            ]
        )

        assert key_set.get_key(kid, algorithm="RS256").key_type == "RSA"
        assert key_set.get_key(kid, algorithm="HS256").key_type == "oct"

        with pytest.raises(PyJWKSetAmbiguousKeyError):
            key_set.get_key(kid)

    def test_ambiguous_error_is_a_jwk_set_error(self) -> None:
        assert issubclass(PyJWKSetAmbiguousKeyError, PyJWKSetError)
