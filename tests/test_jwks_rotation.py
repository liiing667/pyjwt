import json
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any
from unittest import mock
from urllib.error import URLError

import pytest

import jwt
from jwt import PyJWKClient
from jwt.exceptions import (
    InvalidSignatureError,
    PyJWKClientConnectionError,
    PyJWKClientError,
    PyJWKSetError,
)

from .utils import crypto_required, key_path


ROTATION_KEYS = Path(key_path("jwks_rotation"))
ROTATION_KID = "rotating-key"


def _load_jwks(name: str) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((ROTATION_KEYS / f"{name}_jwks.json").read_text())
    return data


def _load_token(name: str) -> str:
    return (ROTATION_KEYS / f"{name}_token.jwt").read_text().strip()


OLD_JWKS = _load_jwks("old")
NEW_JWKS = _load_jwks("new")
OLD_TOKEN = _load_token("old")
NEW_TOKEN = _load_token("new")


@contextmanager
def mocked_responses(payloads: list[dict[str, Any]]) -> Iterator[mock.Mock]:
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        response = mock.Mock()
        response.__enter__ = mock.Mock(return_value=response)
        response.__exit__ = mock.Mock()
        response.read.side_effect = [json.dumps(payload) for payload in payloads]
        urlopen_mock.return_value = response
        yield urlopen_mock


@contextmanager
def mocked_connection_failure() -> Iterator[mock.Mock]:
    with mock.patch("urllib.request.build_opener") as build_opener_mock:
        opener = mock.Mock()
        build_opener_mock.return_value = opener
        urlopen_mock = opener.open
        urlopen_mock.side_effect = URLError("Fail to process the request.")
        yield urlopen_mock


def _decode(token: str, signing_key: Any) -> dict[str, Any]:
    return jwt.decode(token, signing_key.key, algorithms=["RS256"])


@crypto_required
class TestSigningKeyCacheGeneration:
    def test_same_kid_rotation_rejects_old_token_and_accepts_new(self) -> None:
        # Regression: the per-key LRU used to keep the old public key after a
        # same-`kid` rotation, so a revoked signature kept verifying. The key
        # cache must follow the JWK Set generation instead.
        url = "https://idp.example.test/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, cache_keys=True, lifespan=1)

        with mocked_responses([OLD_JWKS]):
            old_signing_key = jwks_client.get_signing_key_from_jwt(OLD_TOKEN)
        assert _decode(OLD_TOKEN, old_signing_key)["sub"] == "rotation-test"

        # The JWKS endpoint rotates the key material while reusing the kid.
        time.sleep(1.1)
        with mocked_responses([NEW_JWKS]):
            new_signing_key = jwks_client.get_signing_key_from_jwt(NEW_TOKEN)

        # Freshly issued tokens verify against the rotated public key.
        assert _decode(NEW_TOKEN, new_signing_key)["sub"] == "rotation-test"

        # Tokens signed by the revoked key must no longer verify, including
        # a second lookup that is still served entirely from the key cache.
        with mocked_responses([]) as calls:
            cached_signing_key = jwks_client.get_signing_key(ROTATION_KID)
            assert calls.call_count == 0
        with pytest.raises(InvalidSignatureError):
            _decode(OLD_TOKEN, cached_signing_key)

    def test_repeated_requests_hit_the_key_cache_within_a_generation(self) -> None:
        url = "https://idp.example.test/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, cache_keys=True)

        with mocked_responses([OLD_JWKS]) as calls:
            first = jwks_client.get_signing_key(ROTATION_KID)
            second = jwks_client.get_signing_key(ROTATION_KID)

        assert calls.call_count == 1
        assert second is first

        # A token-driven lookup resolves the same cached key without another
        # network request.
        with mocked_responses([]) as calls:
            from_token = jwks_client.get_signing_key_from_jwt(OLD_TOKEN)
        assert calls.call_count == 0
        assert from_token is first

    def test_failed_refresh_keeps_the_last_verifiable_generation(self) -> None:
        # A transient outage after the JWK Set expires must not wipe the
        # previously resolved signing key: the cached generation stays
        # available and keeps verifying tokens it issued.
        url = "https://idp.example.test/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, cache_keys=True, lifespan=1)

        with mocked_responses([OLD_JWKS]):
            signing_key = jwks_client.get_signing_key(ROTATION_KID)

        time.sleep(1.1)
        with mocked_connection_failure() as failed_calls:
            recovered_key = jwks_client.get_signing_key(ROTATION_KID)
        assert failed_calls.call_count == 1
        assert recovered_key is signing_key
        assert _decode(OLD_TOKEN, recovered_key)["sub"] == "rotation-test"

        # Repeated calls keep serving the retained generation from cache
        # instead of attempting another failing fetch.
        with mocked_responses([]) as calls:
            again = jwks_client.get_signing_key(ROTATION_KID)
        assert calls.call_count == 0
        assert again is signing_key

    def test_failed_initial_fetch_without_cached_generation_raises(self) -> None:
        url = "https://idp.example.test/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, cache_keys=True)

        with pytest.raises(PyJWKClientConnectionError):
            with mocked_connection_failure():
                jwks_client.get_signing_key(ROTATION_KID)

    def test_generation_advances_only_on_successful_cache_puts(self) -> None:
        jwks_client = PyJWKClient("https://idp.example.test/.well-known/jwks.json")
        cache = jwks_client.jwk_set_cache
        assert cache is not None
        initial_generation = cache.generation

        # Invalid payloads are rejected without disturbing the generation.
        with pytest.raises(PyJWKSetError):
            cache.put({"keys": []})
        assert cache.generation == initial_generation

        cache.put(OLD_JWKS)
        first_generation = cache.generation
        assert first_generation > initial_generation

        cache.put(NEW_JWKS)
        assert cache.generation > first_generation

        cached = cache.get()
        assert cached is not None
        assert cached[ROTATION_KID].key_id == ROTATION_KID

        cache.put(None)
        assert cache.get() is None
        assert cache.generation > first_generation + 1

    def test_rotation_is_detected_even_when_cache_has_not_expired(self) -> None:
        # A successful forced refresh (e.g. an unknown kid triggered one)
        # advances the generation, so the key LRU is invalidated immediately
        # rather than waiting for the JWK Set lifespan to elapse.
        url = "https://idp.example.test/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, cache_keys=True, lifespan=300)

        with mocked_responses([OLD_JWKS, NEW_JWKS]):
            old_signing_key = jwks_client.get_signing_key(ROTATION_KID)
            refreshed = jwks_client.get_jwk_set(refresh=True)
            new_signing_key = jwks_client.get_signing_key(ROTATION_KID)

        assert new_signing_key is not old_signing_key
        assert refreshed[ROTATION_KID].key is new_signing_key.key
        assert _decode(NEW_TOKEN, new_signing_key)["sub"] == "rotation-test"
        with pytest.raises(InvalidSignatureError):
            _decode(OLD_TOKEN, new_signing_key)

    def test_unknown_kid_refresh_rebinds_the_key_cache_to_new_generation(
        self,
    ) -> None:
        # The unknown-`kid` forced-refresh path also replaces the JWK Set and
        # must rebind (not poison) the signing-key LRU.
        url = "https://idp.example.test/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, cache_keys=True, cooldown_duration=0)

        with mocked_responses([OLD_JWKS, NEW_JWKS]) as calls:
            first = jwks_client.get_signing_key(ROTATION_KID)
            # A lookup for a missing kid forces one refresh, which replaces
            # the JWK Set with the rotated generation before failing.
            with pytest.raises(PyJWKClientError):
                jwks_client.get_signing_key("not-in-old-set")
            # The same-`kid` key now resolves from the rotated set.
            rotated = jwks_client.get_signing_key(ROTATION_KID)
            # The second lookup for the rotating kid must hit the LRU without
            # another fetch and return the rotated key.
            again = jwks_client.get_signing_key(ROTATION_KID)

        assert rotated is not first
        assert again is rotated
        assert calls.call_count == 2
        assert _decode(NEW_TOKEN, again)["sub"] == "rotation-test"
        with pytest.raises(InvalidSignatureError):
            _decode(OLD_TOKEN, again)

    def test_key_cache_without_jwk_set_cache_keeps_historical_lru_behavior(
        self,
    ) -> None:
        # With Tier 1 disabled there is no generation to bind to; preserve
        # the previous LRU semantics instead of inventing a refresh path.
        url = "https://idp.example.test/.well-known/jwks.json"
        jwks_client = PyJWKClient(url, cache_keys=True, cache_jwk_set=False)

        with mocked_responses([OLD_JWKS, OLD_JWKS]) as calls:
            first = jwks_client.get_signing_key(ROTATION_KID)
            second = jwks_client.get_signing_key(ROTATION_KID)

        assert second is first
        assert calls.call_count == 1
