"""The shared test vectors through the Python binding (DESIGN.md M1).

The checks match `crates/engine/tests/vectors.rs`, so a marshalling fault in
the binding (bytes, optional values, lists, errors) fails here.
"""

from __future__ import annotations

from typing import Any

import pytest
import snailfish as sf
from conftest import load


def _parties(p: Any) -> tuple[dict[str, bytes], dict[str, bytes]]:
    """Return the public signing keys by name and the sealing seeds by ID."""
    sign: dict[str, bytes] = {}
    seal: dict[str, bytes] = {}
    for d in p["devices"]:
        pk = sf.sign_public_key(bytes.fromhex(d["sign_seed"]))
        spk = sf.seal_public_key(bytes.fromhex(d["seal_seed"]))
        assert sf.device_id(pk, spk) == d["id"]
        sign[d["name"]] = pk
        seal[d["id"]] = bytes.fromhex(d["seal_seed"])
    for r in p["recovery"]:
        secret = sf.recovery_parse(r["display"])
        assert sf.recovery_display(secret) == r["display"]
        sign_seed, seal_seed = sf.recovery_derive(secret)
        pk = sf.sign_public_key(sign_seed)
        assert sf.recovery_id(pk, sf.seal_public_key(seal_seed)) == r["id"]
        sign[r["name"]] = pk
        seal[r["id"]] = seal_seed
    return sign, seal


def test_frames(protocol: Any) -> None:
    for f in protocol["frames"]:
        parts = [bytes.fromhex(x) for x in f["parts"]]
        assert sf.frame(parts) == bytes.fromhex(f["frame"])


def test_log_chain_signatures_key_sets_and_ciphertexts(protocol: Any) -> None:
    sign, seal = _parties(protocol)
    log = protocol["log"]
    plaintexts = {c["entry"]: c["plaintext"] for c in protocol["ciphertexts"]}
    digest = sf.digest0(log["log_id"])
    assert digest.hex() == log["digest0"]
    opened = 0
    for e in log["entries"]:
        env = sf.parse_envelope(e["envelope"].encode())
        assert sf.verify_record(
            sign[e["signer"]], env.payload_type, env.payload, env.sig
        )
        info = sf.check_payload(env.payload_type, env.payload)
        assert info.log == log["log_id"]
        assert sf.envelope_to_json(env, info.author) == e["envelope"]
        rh = sf.record_hash(env.payload_type, env.payload, env.sig)
        assert rh.hex() == e["record_hash"]
        assert (info.change_id or b"").hex() == e["change_id"]
        eh = sf.entry_hash(env.payload_type, info.change_id, rh)
        assert eh.hex() == e["entry_hash"]
        digest = sf.digest_next(digest, e["position"], eh)
        assert digest.hex() == e["digest"]
        for ks in info.key_sets:
            keys = sf.open_key_set(
                seal[ks.to], log["log_id"], ks.to, ks.epochs, ks.sealed
            )
            for epoch, key in zip(ks.epochs, keys, strict=True):
                assert key.hex() == log["app_keys"][str(epoch)]
                commitment = sf.key_commitment(log["log_id"], epoch, key)
                assert commitment.hex() == log["commitments"][str(epoch)]
            opened += 1
        if e["position"] in plaintexts:
            epoch = "2" if e["name"] == "change-epoch-2" else "1"
            key = bytes.fromhex(log["app_keys"][epoch])
            plain = sf.decrypt_payload(key, env.payload_type, env.payload)
            assert plain.hex() == plaintexts[e["position"]]
    assert opened == len(protocol["key_sets"])


def test_statements(protocol: Any) -> None:
    sign, _ = _parties(protocol)
    for st in protocol["statements"]:
        env = sf.parse_envelope(st["envelope"].encode())
        assert sf.verify_record(
            sign[st["signer"]], env.payload_type, env.payload, env.sig
        )
        sf.check_statement(env.payload_type, env.payload)


def test_envelope_variants(protocol: Any) -> None:
    for e in protocol["envelopes"]:
        if not e["valid"]:
            with pytest.raises(sf.SnailfishError.Invalid):
                sf.parse_envelope(e["envelope"].encode())
            continue
        env = sf.parse_envelope(e["envelope"].encode())
        assert (
            sf.record_hash(env.payload_type, env.payload, env.sig).hex()
            == e["record_hash"]
        )


def _payload_bytes(case: Any) -> bytes:
    if case["payload"] is None:
        return bytes.fromhex(case["payload_hex"])
    return case["payload"].encode()


@pytest.mark.parametrize(
    "case", load("strict-json.json")["cases"], ids=lambda c: c["name"]
)
def test_strict_json(case: Any) -> None:
    if case["valid"]:
        sf.check_payload(case["payload_type"], _payload_bytes(case))
    else:
        with pytest.raises(sf.SnailfishError.Invalid):
            sf.check_payload(case["payload_type"], _payload_bytes(case))


def test_recovery_keys() -> None:
    v = load("recovery-key.json")
    for c in v["valid"]:
        assert sf.recovery_parse(c["text"]).hex() == c["secret"]
    for c in v["invalid"]:
        with pytest.raises(sf.SnailfishError.Invalid):
            sf.recovery_parse(c["text"])


def test_cctv_ed25519() -> None:
    vectors = load("third_party/cctv-ed25519.json")
    assert len(vectors) == 914
    allowed = {"low_order_component_A", "low_order_component_R"}
    for t in vectors:
        expected = set(t["flags"] or []) <= allowed
        got = sf.ed25519_verify(
            bytes.fromhex(t["key"]), t["msg"].encode(), bytes.fromhex(t["sig"])
        )
        assert got == expected, t["number"]


def test_payload_classes() -> None:
    assert sf.classify("snailfish.change.v1") == sf.PayloadClass.RECORD
    assert sf.classify("snailfish.change.v2") == sf.PayloadClass.UNKNOWN_CONTENT
    assert sf.classify("snailfish.grant.v2") == sf.PayloadClass.UPDATE_REQUIRED
