import copy
import json
from typing import Any

import pytest

from jwt.algorithms import has_crypto
from jwt.api_jwk import PyJWK, PyJWKSet
from jwt.exceptions import (
    InvalidKeyError,
    MissingCryptographyError,
    PyJWKError,
    PyJWKSetError,
)

from .utils import crypto_required, key_path, no_crypto_required

if has_crypto:
    from jwt.algorithms import ECAlgorithm, HMACAlgorithm, OKPAlgorithm, RSAAlgorithm


class TestPyJWK:
    @crypto_required
    def test_should_load_key_from_jwk_data_dict(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_key_from_jwk_data_json_string(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk = PyJWK.from_json(json.dumps(key_data))

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_key_without_alg_from_dict(self) -> None:
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "RSA"
        assert isinstance(jwk.Algorithm, RSAAlgorithm)
        assert jwk.Algorithm.hash_alg == RSAAlgorithm.SHA256
        assert jwk.algorithm_name == "RS256"

    @crypto_required
    def test_should_load_key_from_dict_with_algorithm(self) -> None:
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data, algorithm="RS256")

        assert jwk.key_type == "RSA"
        assert isinstance(jwk.Algorithm, RSAAlgorithm)
        assert jwk.Algorithm.hash_alg == RSAAlgorithm.SHA256
        assert jwk.algorithm_name == "RS256"

    @crypto_required
    def test_should_load_key_ec_p256_from_dict(self) -> None:
        with open(key_path("jwk_ec_pub_P-256.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA256
        assert jwk.algorithm_name == "ES256"

    @crypto_required
    def test_should_load_key_ec_p384_from_dict(self) -> None:
        with open(key_path("jwk_ec_pub_P-384.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA384
        assert jwk.algorithm_name == "ES384"

    @crypto_required
    def test_should_load_key_ec_p521_from_dict(self) -> None:
        with open(key_path("jwk_ec_pub_P-521.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA512
        assert jwk.algorithm_name == "ES512"

    @crypto_required
    def test_should_load_key_ec_secp256k1_from_dict(self) -> None:
        with open(key_path("jwk_ec_pub_secp256k1.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "EC"
        assert isinstance(jwk.Algorithm, ECAlgorithm)
        assert jwk.Algorithm.hash_alg == ECAlgorithm.SHA256
        assert jwk.algorithm_name == "ES256K"

    @crypto_required
    def test_should_load_key_hmac_from_dict(self) -> None:
        with open(key_path("jwk_hmac.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "oct"
        assert isinstance(jwk.Algorithm, HMACAlgorithm)
        assert jwk.Algorithm.hash_alg == HMACAlgorithm.SHA256
        assert jwk.algorithm_name == "HS256"

    @crypto_required
    def test_should_load_key_hmac_without_alg_from_dict(self) -> None:
        with open(key_path("jwk_hmac.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        del key_data["alg"]
        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "oct"
        assert isinstance(jwk.Algorithm, HMACAlgorithm)
        assert jwk.Algorithm.hash_alg == HMACAlgorithm.SHA256
        assert jwk.algorithm_name == "HS256"

    @crypto_required
    def test_should_load_key_okp_without_alg_from_dict(self) -> None:
        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            key_data = json.loads(keyfile.read())

        jwk = PyJWK.from_dict(key_data)

        assert jwk.key_type == "OKP"
        assert isinstance(jwk.Algorithm, OKPAlgorithm)
        assert jwk.algorithm_name == "EdDSA"

    @crypto_required
    def test_from_dict_should_throw_exception_if_arg_is_invalid(self) -> None:
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            valid_rsa_pub = json.loads(keyfile.read())
        with open(key_path("jwk_ec_pub_P-256.json")) as keyfile:
            valid_ec_pub = json.loads(keyfile.read())
        with open(key_path("jwk_okp_pub_Ed25519.json")) as keyfile:
            valid_okp_pub = json.loads(keyfile.read())

        # Unknown algorithm
        with pytest.raises(PyJWKError):
            PyJWK.from_dict(valid_rsa_pub, algorithm="unknown")

        # Missing kty
        v = valid_rsa_pub.copy()
        del v["kty"]
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown kty
        v = valid_rsa_pub.copy()
        v["kty"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown EC crv
        v = valid_ec_pub.copy()
        v["crv"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Unknown OKP crv
        v = valid_okp_pub.copy()
        v["crv"] = "unknown"
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

        # Missing OKP crv
        v = valid_okp_pub.copy()
        del v["crv"]
        with pytest.raises(InvalidKeyError):
            PyJWK.from_dict(v)

    @no_crypto_required
    def test_missing_crypto_library_good_error_message(self) -> None:
        with pytest.raises(PyJWKError) as exc:
            PyJWK({"kty": "dummy"}, algorithm="RS256")
            assert "cryptography" in str(exc.value)

    @no_crypto_required
    def test_missing_crypto_library_raises_missing_cryptography_error(self) -> None:
        with pytest.raises(MissingCryptographyError):
            PyJWK({"kty": "dummy"}, algorithm="RS256")


class TestPyJWKSet:
    @crypto_required
    def test_should_skip_malformed_rsa_key_and_load_remaining_keys(self) -> None:
        with open(key_path("jwk_rsa_key.json")) as keyfile:
            malformed_key = json.loads(keyfile.read())

        malformed_key["d"] = "AAAAAA"
        for parameter in ("p", "q", "dp", "dq", "qi"):
            del malformed_key[parameter]

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            valid_key = json.loads(keyfile.read())

        jwk_set = PyJWKSet.from_dict({"keys": [malformed_key, valid_key]})

        assert len(jwk_set.keys) == 1
        assert jwk_set.keys[0].key_type == "RSA"

    @crypto_required
    def test_should_load_keys_from_jwk_data_dict(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})
        jwk = jwk_set.keys[0]

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_should_load_keys_from_jwk_data_json_string(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_json(json.dumps({"keys": [key_data]}))
        jwk = jwk_set.keys[0]

        assert jwk.key_type == "RSA"
        assert jwk.key_id == "keyid-abc123"
        assert jwk.public_key_use == "sig"

    @crypto_required
    def test_keyset_should_index_by_kid(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        # TODO Should `to_jwk` set these?
        key_data["alg"] = "RS256"
        key_data["use"] = "sig"
        key_data["kid"] = "keyid-abc123"

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})

        jwk = jwk_set.keys[0]
        assert jwk == jwk_set["keyid-abc123"]

        with pytest.raises(KeyError):
            _ = jwk_set["this-kid-does-not-exist"]

    @crypto_required
    def test_keyset_iterator(self) -> None:
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)

        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data_str = algo.to_jwk(pub_key)
        key_data = json.loads(key_data_str)

        jwk_set = PyJWKSet.from_dict({"keys": [key_data]})

        assert jwk_set.keys == [jwk for jwk in jwk_set]

    @crypto_required
    def test_keyset_skips_members_that_are_not_objects(self) -> None:
        # A JWKS member that isn't a JSON object is an unusable key, not a
        # reason to fail the whole set with an uncaught AttributeError.
        algo = RSAAlgorithm(RSAAlgorithm.SHA256)
        with open(key_path("jwk_rsa_pub.json")) as keyfile:
            pub_key = algo.from_jwk(keyfile.read())

        key_data = json.loads(algo.to_jwk(pub_key))
        key_data["alg"] = "RS256"
        key_data["kid"] = "usable"

        keyset = PyJWKSet.from_dict({"keys": [None, "nope", 7, key_data]})

        assert [key.key_id for key in keyset.keys] == ["usable"]

    @crypto_required
    def test_keyset_of_only_non_object_members_raises_set_error(self) -> None:
        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_dict({"keys": [None]})

    @crypto_required
    def test_keyset_skips_members_with_invalid_component_types(self) -> None:
        # RSA components must be strings; a number is unusable and must not
        # surface as an uncaught TypeError.
        with pytest.raises(PyJWKSetError):
            PyJWKSet.from_dict({"keys": [{"kty": "RSA", "n": 1, "e": "AQAB"}]})

    @crypto_required
    def test_jwk_with_invalid_component_type_raises_invalid_key_error(self) -> None:
        with pytest.raises(InvalidKeyError):
            PyJWK({"kty": "RSA", "alg": "RS256", "n": 1, "e": "AQAB"})

    @crypto_required
    def test_keyset_with_unknown_alg(self) -> None:
        # first keyset with unusable key and usable key
        with open(key_path("jwk_keyset_with_unknown_alg.json")) as keyfile:
            jwks_text = keyfile.read()
        jwks = json.loads(jwks_text)
        assert len(jwks.get("keys")) == 2
        keyset = PyJWKSet.from_json(jwks_text)
        assert len(keyset.keys) == 1

        # second keyset with only unusable key -> catch exception
        with open(key_path("jwk_keyset_only_unknown_alg.json")) as keyfile:
            jwks_text = keyfile.read()
            jwks = json.loads(jwks_text)
            assert len(jwks.get("keys")) == 1
            with pytest.raises(PyJWKSetError):
                _ = PyJWKSet.from_json(jwks_text)

    @crypto_required
    def test_invalid_keys_list(self) -> None:
        with pytest.raises(PyJWKSetError) as err:
            PyJWKSet(keys="string")  # type: ignore[arg-type]
        assert str(err.value) == "Invalid JWK Set value"

    @crypto_required
    def test_empty_keys_list(self) -> None:
        with pytest.raises(PyJWKSetError) as err:
            PyJWKSet(keys=[])
        assert str(err.value) == "The JWK Set did not contain any keys"

    @no_crypto_required
    def test_missing_crypto_library_raises_when_required(self) -> None:
        with pytest.raises(MissingCryptographyError):
            PyJWKSet(keys=[{"kty": "RSA"}])


def _load_jwk_fixture(name: str) -> dict[str, Any]:
    with open(key_path(name)) as keyfile:
        return json.loads(keyfile.read())


@pytest.fixture(scope="module")
def ambiguous_matrix() -> dict[str, Any]:
    shared_kid = "shared-kid"
    rsa_sig = copy.deepcopy(_load_jwk_fixture("jwk_rsa_pub.json"))
    rsa_sig.update(kid=shared_kid, use="sig", alg="RS256")

    rsa_cert = copy.deepcopy(rsa_sig)
    rsa_cert["x5c"] = ["MIIBdummyCertificateChain"]

    rsa_private_sig = copy.deepcopy(_load_jwk_fixture("jwk_rsa_key.json"))
    rsa_private_sig.update(kid=shared_kid, use="sig", alg="RS256")

    ec_sig = copy.deepcopy(_load_jwk_fixture("jwk_ec_pub_P-256.json"))
    ec_sig.update(kid=shared_kid, use="sig")

    hmac_sig = copy.deepcopy(_load_jwk_fixture("jwk_hmac.json"))
    hmac_sig["kid"] = shared_kid

    return {
        "kid": shared_kid,
        "keys": [rsa_sig, rsa_cert, rsa_private_sig, ec_sig, hmac_sig],
        "rsa_sig": rsa_sig,
        "rsa_cert": rsa_cert,
        "rsa_private_sig": rsa_private_sig,
        "ec_sig": ec_sig,
        "hmac_sig": hmac_sig,
    }


@pytest.fixture(scope="module")
def ambiguous_jwk_set(ambiguous_matrix: dict[str, Any]) -> PyJWKSet:
    return PyJWKSet.from_dict({"keys": ambiguous_matrix["keys"]})


@crypto_required
class TestPyJWKSetAmbiguousKid:
    """Selection over a fixed JWK Set whose members share one ``kid``.

    The matrix deliberately contains the members that a naive "first match
    on ``kid``" lookup confuses: an RSA public key, its private counterpart,
    an EC public key, an HMAC secret and an X.509-backed copy of the RSA
    public key. Every case below pins down either an exact hit or a
    fail-closed rejection.
    """

    def test_members_keep_their_distinct_shapes(
        self,
        ambiguous_jwk_set: PyJWKSet,
        ambiguous_matrix: dict[str, Any],
    ) -> None:
        by_shape = {
            (
                key.key_type,
                key.algorithm_name,
                key.is_private_key,
                key.has_certificate_chain,
            ): key
            for key in ambiguous_jwk_set.keys
        }

        assert len(ambiguous_jwk_set.keys) == 5
        assert {key.key_id for key in ambiguous_jwk_set.keys} == {
            ambiguous_matrix["kid"]
        }
        assert by_shape[("RSA", "RS256", False, False)].public_key_use == "sig"
        assert by_shape[("RSA", "RS256", False, True)].has_certificate_chain
        assert by_shape[("RSA", "RS256", True, False)].is_private_key
        assert by_shape[("EC", "ES256", False, False)].key_type == "EC"
        assert by_shape[("oct", "HS256", False, False)].key_type == "oct"

    @pytest.mark.parametrize(
        ("selector", "expected"),
        [
            ({"algorithm": "ES256"}, ("EC", "ES256", False)),
            ({"algorithm": "HS256"}, ("oct", "HS256", False)),
            ({"key_type": "EC"}, ("EC", "ES256", False)),
            ({"key_type": "oct"}, ("oct", "HS256", False)),
        ],
    )
    def test_find_key_hits_unique_member(
        self,
        ambiguous_jwk_set: PyJWKSet,
        ambiguous_matrix: dict[str, Any],
        selector: dict[str, Any],
        expected: tuple[str, str, bool],
    ) -> None:
        key = ambiguous_jwk_set.find_key(ambiguous_matrix["kid"], **selector)

        assert (key.key_type, key.algorithm_name, key.is_private_key) == expected

    @pytest.mark.parametrize(
        "selector",
        [
            {"algorithm": "ES384"},
            {"key_type": "OKP"},
            {"algorithm": "RS256", "intended_use": "enc"},
        ],
    )
    def test_find_key_rejects_when_no_member_matches(
        self,
        ambiguous_jwk_set: PyJWKSet,
        ambiguous_matrix: dict[str, Any],
        selector: dict[str, Any],
    ) -> None:
        with pytest.raises(KeyError):
            ambiguous_jwk_set.find_key(ambiguous_matrix["kid"], **selector)

    def test_find_key_rejects_unknown_kid(self, ambiguous_jwk_set: PyJWKSet) -> None:
        with pytest.raises(KeyError):
            ambiguous_jwk_set.find_key("kid-not-in-set")

    @pytest.mark.parametrize(
        "selector",
        [
            {},
            {"key_type": "RSA"},
            {"algorithm": "RS256"},
            {"algorithm": "RS256", "allow_private": True},
            {"algorithm": "RS256", "key_type": "RSA", "allow_private": True},
        ],
    )
    def test_find_key_fails_closed_on_ambiguity(
        self,
        ambiguous_jwk_set: PyJWKSet,
        ambiguous_matrix: dict[str, Any],
        selector: dict[str, Any],
    ) -> None:
        with pytest.raises(PyJWKSetError, match="ambiguous"):
            ambiguous_jwk_set.find_key(ambiguous_matrix["kid"], **selector)

    def test_indexing_uses_the_same_strict_selection(
        self, ambiguous_jwk_set: PyJWKSet, ambiguous_matrix: dict[str, Any]
    ) -> None:
        # A disambiguated lookup still works through __getitem__'s kid-only
        # contract when the set has a single member for the kid.
        unique = copy.deepcopy(_load_jwk_fixture("jwk_ec_pub_P-256.json"))
        unique.update(kid="single-kid", use="sig")
        single_member_set = PyJWKSet.from_dict({"keys": [unique]})

        assert single_member_set["single-kid"].key_id == "single-kid"

        with pytest.raises(KeyError):
            single_member_set["missing-kid"]

        with pytest.raises(PyJWKSetError, match="ambiguous"):
            ambiguous_jwk_set[ambiguous_matrix["kid"]]

    def test_matches_checks_every_selector(
        self, ambiguous_matrix: dict[str, Any]
    ) -> None:
        kid = ambiguous_matrix["kid"]
        private_key = PyJWK(ambiguous_matrix["rsa_private_sig"])
        public_key = PyJWK(ambiguous_matrix["rsa_sig"])
        ec_key = PyJWK(ambiguous_matrix["ec_sig"])

        assert public_key.matches(kid, algorithm="RS256")
        assert not public_key.matches(kid, algorithm="ES256")
        assert not public_key.matches("other-kid", algorithm="RS256")
        assert not public_key.matches(kid, intended_use="enc")
        assert not private_key.matches(kid, algorithm="RS256")
        assert private_key.matches(kid, algorithm="RS256", allow_private=True)
        assert ec_key.matches(kid, key_type="EC")
        assert not ec_key.matches(kid, key_type="RSA")

    def test_legitimate_rotation_with_distinct_kids_still_resolves(self) -> None:
        first = copy.deepcopy(_load_jwk_fixture("jwk_rsa_pub.json"))
        first.update(kid="rotation-kid-1", use="sig", alg="RS256")
        second = copy.deepcopy(_load_jwk_fixture("jwk_ec_pub_P-256.json"))
        second.update(kid="rotation-kid-2", use="sig")

        rotating_set = PyJWKSet.from_dict({"keys": [first, second]})

        assert rotating_set.find_key("rotation-kid-1").key_type == "RSA"
        assert rotating_set.find_key("rotation-kid-2").key_type == "EC"
