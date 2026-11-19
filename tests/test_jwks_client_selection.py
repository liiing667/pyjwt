"""Same-``kid`` selection matrix for :class:`jwt.PyJWKClient`.

The client must never pick a key based on its position in the JWK Set. These
tests pin down which members hit and which are rejected when private keys,
public keys, certificates and differing algorithms share a ``kid``, and make
sure legitimate rotation and the per-key LRU cache keep working.
"""

import contextlib
import json
from collections.abc import Iterator
from typing import Any, cast
from unittest import mock

import pytest

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    PyJWKClientAmbiguousKeyError,
    PyJWKClientError,
)

from .utils import crypto_required, key_path

URL = "https://example.com/.well-known/jwks.json"


def _load_jwk(name: str) -> dict[str, Any]:
    with open(key_path(name)) as keyfile:
        return cast(dict[str, Any], json.load(keyfile))


@contextlib.contextmanager
def mocked_jwks(payload: dict[str, Any]) -> Iterator[mock.Mock]:
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock()
        response.read.side_effect = [json.dumps(payload)]
        opener.open.return_value = response
        yield opener.open


@pytest.fixture
def rsa_private() -> dict[str, Any]:
    return _load_jwk("jwk_rsa_key.json")


@pytest.fixture
def rsa_public() -> dict[str, Any]:
    return _load_jwk("jwk_rsa_pub.json")


@pytest.fixture
def ec_public() -> dict[str, Any]:
    return _load_jwk("jwk_ec_pub_P-256.json")


@pytest.fixture
def hmac_key() -> dict[str, Any]:
    return _load_jwk("jwk_hmac.json")


@crypto_required
class TestPyJWKClientSelectionMatrix:
    def test_private_key_sharing_kid_is_never_selected_for_verification(
        self, rsa_private: dict[str, Any], rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        payload = {
            "keys": [
                dict(rsa_private, alg="RS256"),
                dict(rsa_public, alg="RS256"),
            ]
        }

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            chosen = client.get_signing_key(kid, algorithm="RS256")

        assert chosen.key_material == "public"
        assert chosen.has_private_key is False

    def test_private_only_jwks_reports_no_signing_key(
        self, rsa_private: dict[str, Any]
    ) -> None:
        payload = {"keys": [dict(rsa_private, alg="RS256")]}

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            with pytest.raises(PyJWKClientError, match="signing keys"):
                client.get_signing_key(rsa_private["kid"], algorithm="RS256")

    def test_same_kid_two_key_types_fail_closed_without_algorithm(
        self, rsa_public: dict[str, Any], ec_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        payload = {
            "keys": [
                dict(rsa_public, alg="RS256"),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        }

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            with pytest.raises(PyJWKClientAmbiguousKeyError):
                client.get_signing_key(kid)

    def test_ambiguity_fails_without_a_refresh_fetch(
        self, rsa_public: dict[str, Any], ec_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        payload = {
            "keys": [
                dict(rsa_public, alg="RS256"),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        }

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            opener = mock.Mock()
            build_opener_mock.return_value = opener
            response = mock.Mock()
            response.__enter__ = mock.Mock(return_value=response)
            response.__exit__ = mock.Mock()
            response.read.side_effect = [json.dumps(payload)]
            opener.open.return_value = response

            client = PyJWKClient(URL, cooldown_duration=0)
            with pytest.raises(PyJWKClientAmbiguousKeyError):
                client.get_signing_key(kid)

            # A refresh cannot resolve ambiguity inside the same document,
            # so failing closed must not spend a second network request.
            assert opener.open.call_count == 1

    @pytest.mark.parametrize(
        ("algorithm", "expected_kty"),
        [("RS256", "RSA"), ("ES256", "EC")],
    )
    def test_token_algorithm_selects_the_matching_family(
        self,
        rsa_public: dict[str, Any],
        ec_public: dict[str, Any],
        algorithm: str,
        expected_kty: str,
    ) -> None:
        kid = rsa_public["kid"]
        payload = {
            "keys": [
                dict(rsa_public, alg="RS256"),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        }

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            chosen = client.get_signing_key(kid, algorithm=algorithm)

        assert chosen.key_type == expected_kty

    def test_use_enc_member_is_rejected_for_signature_lookup(
        self, rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        payload = {"keys": [dict(rsa_public, use="enc", alg="RS256")]}

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            with pytest.raises(PyJWKClientError, match="signing keys"):
                client.get_signing_key(kid, algorithm="RS256")

    def test_certificate_member_is_distinct_from_plain_public_key(
        self, rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        payload = {
            "keys": [
                dict(rsa_public, alg="RS256"),
                dict(rsa_public, alg="RS256", x5c=["MIIB"], x5t="t"),
            ]
        }

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            with pytest.raises(PyJWKClientAmbiguousKeyError):
                client.get_signing_key(kid, algorithm="RS256")

    def test_duplicate_identical_member_resolves_normally(
        self, rsa_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        member = dict(rsa_public, alg="RS256")
        payload = {"keys": [dict(member), dict(member)]}

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            chosen = client.get_signing_key(kid, algorithm="RS256")

        assert chosen.key_id == kid

    def test_rotation_window_with_distinct_kids_resolves_both(
        self, rsa_public: dict[str, Any]
    ) -> None:
        payload = {
            "keys": [
                dict(rsa_public, kid="rotation-old", alg="RS256"),
                dict(rsa_public, kid="rotation-new", alg="RS256"),
            ]
        }

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            old = client.get_signing_key("rotation-old", algorithm="RS256")
            new = client.get_signing_key("rotation-new", algorithm="RS256")

        assert old.key_id == "rotation-old"
        assert new.key_id == "rotation-new"

    def test_lru_cache_keeps_algorithm_specific_keys_separate(
        self, rsa_public: dict[str, Any], ec_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        payload = {
            "keys": [
                dict(rsa_public, alg="RS256"),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        }

        with mock.patch("urllib.request.build_opener") as build_opener_mock:
            opener = mock.Mock()
            build_opener_mock.return_value = opener
            response = mock.Mock()
            response.__enter__ = mock.Mock(return_value=response)
            response.__exit__ = mock.Mock()
            response.read.side_effect = [
                json.dumps(payload),
                json.dumps(payload),
            ]
            opener.open.return_value = response

            client = PyJWKClient(URL, cache_keys=True)
            rsa_key = client.get_signing_key(kid, algorithm="RS256")
            ec_key = client.get_signing_key(kid, algorithm="ES256")

            assert rsa_key.key_type == "RSA"
            assert ec_key.key_type == "EC"
            assert rsa_key is not ec_key

            # The second round must be served from the per-key LRU cache
            # without another network fetch.
            assert client.get_signing_key(kid, algorithm="RS256") is rsa_key
            assert client.get_signing_key(kid, algorithm="ES256") is ec_key
            assert opener.open.call_count == 1

    def test_get_signing_key_from_jwt_uses_header_algorithm(
        self,
        rsa_private: dict[str, Any],
        rsa_public: dict[str, Any],
        ec_public: dict[str, Any],
    ) -> None:
        kid = rsa_public["kid"]
        payload = {
            "keys": [
                dict(rsa_public, alg="RS256"),
                dict(ec_public, kid=kid, alg="ES256"),
            ]
        }
        rsa_signing_key = jwt.api_jwk.PyJWK(dict(rsa_private, alg="RS256")).key
        ec_private = _load_jwk("jwk_ec_key_P-256.json")
        ec_signing_key = jwt.api_jwk.PyJWK(dict(ec_private, alg="ES256")).key

        rsa_token = jwt.encode(
            {"sub": "rsa"},
            rsa_signing_key,
            algorithm="RS256",
            headers={"kid": kid},
        )
        ec_token = jwt.encode(
            {"sub": "ec"},
            ec_signing_key,
            algorithm="ES256",
            headers={"kid": kid},
        )

        with mocked_jwks(payload):
            client = PyJWKClient(URL)
            rsa_key = client.get_signing_key_from_jwt(rsa_token)
            ec_key = client.get_signing_key_from_jwt(ec_token)

        assert rsa_key.key_type == "RSA"
        assert ec_key.key_type == "EC"

    def test_match_kid_returns_none_or_raises_on_ambiguity(
        self, rsa_public: dict[str, Any], ec_public: dict[str, Any]
    ) -> None:
        kid = rsa_public["kid"]
        keys = [
            jwt.api_jwk.PyJWK(dict(rsa_public, alg="RS256")),
            jwt.api_jwk.PyJWK(dict(ec_public, kid=kid, alg="ES256")),
        ]

        assert PyJWKClient.match_kid(keys, "missing") is None
        with pytest.raises(PyJWKClientAmbiguousKeyError):
            PyJWKClient.match_kid(keys, kid)
        ec_match = PyJWKClient.match_kid(keys, kid, algorithm="ES256")
        assert ec_match is not None
        assert ec_match.key_type == "EC"

    def test_ambiguous_error_is_a_client_error(self) -> None:
        assert issubclass(PyJWKClientAmbiguousKeyError, PyJWKClientError)
