import hashlib
import hmac
import json
import os

import pytest

import jwt as pyjwt
from jwt.exceptions import DecodeError
from jwt.utils import (
    DEFAULT_MAX_JSON_DEPTH,
    DEFAULT_MAX_JSON_MEMBERS,
    base64url_encode,
    json_loads_strict_object,
)

FIXTURE_DIR = os.path.join(
    os.path.dirname(os.path.realpath(__file__)), "fixtures", "strict_json"
)

SECRET = b"test-secret-key-that-is-long-enough"


def fixture_bytes(name: str) -> bytes:
    with open(os.path.join(FIXTURE_DIR, name), "rb") as fixture_file:
        return fixture_file.read()


def make_token(header_json: bytes, payload_json: bytes, key: bytes = SECRET) -> bytes:
    signing_input = (
        base64url_encode(header_json) + b"." + base64url_encode(payload_json)
    )
    signature = hmac.new(key, signing_input, hashlib.sha256).digest()
    return signing_input + b"." + base64url_encode(signature)


GOOD_HEADER = b'{"alg": "HS256", "typ": "JWT"}'
GOOD_PAYLOAD = b'{"sub": "alice", "admin": false}'


class TestStrictJsonParser:
    def test_valid_legacy_document_is_accepted(self):
        result = json_loads_strict_object(fixture_bytes("valid_legacy.json"))
        assert result["sub"] == "user-123"
        assert result["custom"]["nested"]["list"] == [1, 2, {"three": 3}]

    def test_duplicate_key_is_rejected(self):
        with pytest.raises(ValueError, match="Duplicate JSON object key"):
            json_loads_strict_object(fixture_bytes("duplicate_key.json"))

    def test_nested_duplicate_key_is_rejected(self):
        with pytest.raises(ValueError, match="Duplicate JSON object key"):
            json_loads_strict_object(fixture_bytes("nested_duplicate_key.json"))

    def test_nesting_at_limit_is_accepted(self):
        result = json_loads_strict_object(fixture_bytes("nested_at_limit.json"))
        depth = 0
        node = result
        while isinstance(node, dict):
            depth += 1
            node = node["a"]
        assert depth == DEFAULT_MAX_JSON_DEPTH

    def test_nesting_over_limit_is_rejected(self):
        with pytest.raises(ValueError, match="nesting depth exceeds limit"):
            json_loads_strict_object(fixture_bytes("nested_over_limit.json"))

    def test_too_many_members_is_rejected(self):
        with pytest.raises(ValueError, match="member count exceeds limit"):
            json_loads_strict_object(fixture_bytes("too_many_members.json"))

    def test_member_count_at_limit_is_accepted(self):
        doc = {f"claim_{i:04d}": i for i in range(DEFAULT_MAX_JSON_MEMBERS)}
        result = json_loads_strict_object(json.dumps(doc))
        assert result == doc

    def test_limits_are_configurable(self):
        with pytest.raises(ValueError, match="member count exceeds limit"):
            json_loads_strict_object('{"a": 1, "b": 2}', max_members=1)
        with pytest.raises(ValueError, match="nesting depth exceeds limit"):
            json_loads_strict_object('{"a": {"b": 1}}', max_depth=1)

    def test_arrays_count_towards_depth(self):
        with pytest.raises(ValueError, match="nesting depth exceeds limit"):
            json_loads_strict_object('{"a": [[[{"b": 1}]]]}', max_depth=4)

    def test_non_object_top_level_is_returned_for_caller_validation(self):
        # Type validation stays with the callers; the parser only enforces
        # duplicate/member/depth rules.
        assert json_loads_strict_object("[1, 2]") == [1, 2]


class TestStrictHeaderParsing:
    def test_duplicate_key_in_header_fails_closed(self):
        header = b'{"alg": "HS256", "alg": "none"}'
        token = make_token(header, GOOD_PAYLOAD)
        with pytest.raises(DecodeError, match="Invalid header string"):
            pyjwt.decode(token, SECRET, algorithms=["HS256"])

    def test_duplicate_key_in_header_rejected_before_signature_verification(self):
        # Garbage signature: parsing must fail before it is ever checked.
        header = b'{"alg": "HS256", "typ": "JWT", "typ": "XXS"}'
        token = (
            base64url_encode(header)
            + b"."
            + base64url_encode(GOOD_PAYLOAD)
            + b".invalidsignature"
        )
        with pytest.raises(DecodeError, match="Invalid header string"):
            pyjwt.decode(token, SECRET, algorithms=["HS256"])

    def test_get_unverified_header_uses_strict_parsing(self):
        header = b'{"alg": "HS256", "kid": "a", "kid": "b"}'
        token = make_token(header, GOOD_PAYLOAD)
        with pytest.raises(DecodeError, match="Invalid header string"):
            pyjwt.get_unverified_header(token)

    def test_over_limit_header_is_rejected(self):
        token = make_token(fixture_bytes("nested_over_limit.json"), GOOD_PAYLOAD)
        with pytest.raises(DecodeError, match="Invalid header string"):
            pyjwt.decode(token, SECRET, algorithms=["HS256"])


class TestStrictPayloadParsing:
    def test_duplicate_key_in_payload_fails_closed(self):
        payload = fixture_bytes("duplicate_key.json")
        token = make_token(GOOD_HEADER, payload)
        with pytest.raises(DecodeError, match="Invalid payload string"):
            pyjwt.decode(token, SECRET, algorithms=["HS256"])

    def test_nested_duplicate_key_in_payload_fails_closed(self):
        payload = fixture_bytes("nested_duplicate_key.json")
        token = make_token(GOOD_HEADER, payload)
        with pytest.raises(DecodeError, match="Invalid payload string"):
            pyjwt.decode_complete(token, SECRET, algorithms=["HS256"])

    def test_over_limit_payload_is_rejected(self):
        token = make_token(GOOD_HEADER, fixture_bytes("too_many_members.json"))
        with pytest.raises(DecodeError, match="Invalid payload string"):
            pyjwt.decode(token, SECRET, algorithms=["HS256"])

    def test_deeply_nested_payload_is_rejected(self):
        token = make_token(GOOD_HEADER, fixture_bytes("nested_over_limit.json"))
        with pytest.raises(DecodeError, match="Invalid payload string"):
            pyjwt.decode(token, SECRET, algorithms=["HS256"])

    def test_same_document_rejected_identically_in_header_and_payload(self):
        document = fixture_bytes("duplicate_key.json")
        header_token = make_token(document, GOOD_PAYLOAD)
        payload_token = make_token(GOOD_HEADER, document)
        with pytest.raises(DecodeError):
            pyjwt.decode(header_token, SECRET, algorithms=["HS256"])
        with pytest.raises(DecodeError):
            pyjwt.decode(payload_token, SECRET, algorithms=["HS256"])


class TestLegacyTokensStillWork:
    def test_encode_decode_roundtrip(self):
        token = pyjwt.encode(
            {"sub": "alice", "roles": ["user", "auditor"], "admin": False},
            SECRET,
            algorithm="HS256",
        )
        decoded = pyjwt.decode(token, SECRET, algorithms=["HS256"])
        assert decoded["sub"] == "alice"
        assert decoded["roles"] == ["user", "auditor"]

    def test_legacy_fixture_token_decodes(self):
        token = make_token(GOOD_HEADER, fixture_bytes("valid_legacy.json"))
        decoded = pyjwt.decode(
            token, SECRET, algorithms=["HS256"], audience="service-a"
        )
        assert decoded["sub"] == "user-123"
        assert decoded["realm_access"]["roles"] == ["user", "auditor"]

    def test_nested_fixture_at_limit_decodes_in_payload(self):
        token = make_token(GOOD_HEADER, fixture_bytes("nested_at_limit.json"))
        decoded = pyjwt.decode(token, SECRET, algorithms=["HS256"])
        assert isinstance(decoded, dict)
