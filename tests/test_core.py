import random

import pytest

from telecloak.core import (TELEGRAM_LIMIT, Channel, Reassembler, Seen, TelecloakError, fingerprint, load_psk,
                            new_psk, open_part)

ME, PEER = 111111, 222222


def pair():
    psk = load_psk(new_psk())
    return Channel(psk, ME, PEER), Channel(psk, PEER, ME)


def roundtrip(a, b, body):
    sealed = a.seal(body)
    r = Reassembler()
    out = None
    for w in sealed.parts:
        out = r.add(b.open(w))
    return sealed, out


def test_roundtrip():
    a, b = pair()
    sealed, msg = roundtrip(a, b, {"kind": "chat", "text": "hello"})
    assert msg.body == {"kind": "chat", "text": "hello"}
    assert msg.msg_id == sealed.msg_id and len(sealed.parts) == 1
    assert sealed.parts[0].startswith("tc1.")


def test_long_message_splits_under_telegram_limit_and_reassembles_out_of_order():
    a, b = pair()
    text = "".join(random.choice("abcé\U0001F600\n\"\\") for _ in range(20000))
    sealed = a.seal({"text": text})
    assert len(sealed.parts) > 1
    assert all(len(w) <= TELEGRAM_LIMIT for w in sealed.parts)
    r = Reassembler()
    parts = [b.open(w) for w in sealed.parts]
    random.shuffle(parts)
    results = [r.add(p) for p in parts]
    assert all(x is None for x in results[:-1])
    assert results[-1].body["text"] == text


def test_reflection_rejected():
    # a message I sent, bounced back to me as if the peer sent it, must not open
    a, _ = pair()
    wire = a.seal({"text": "mine"}).parts[0]
    with pytest.raises(TelecloakError):
        a.open(wire)
    assert a.open(wire, outgoing=True).count == 1   # but I can read my own history


def test_wrong_key_rejected():
    a, _ = pair()
    _, other = pair()
    with pytest.raises(TelecloakError):
        other.open(a.seal({"text": "x"}).parts[0])


def test_third_party_with_same_key_but_other_ids_rejected():
    psk = load_psk(new_psk())
    a = Channel(psk, ME, PEER)
    eve = Channel(psk, 333333, ME)   # right key, claims to be someone else
    with pytest.raises(TelecloakError):
        a.open(eve.seal({"text": "x"}).parts[0])


def test_tamper_rejected():
    a, b = pair()
    wire = a.seal({"text": "pay 10"}).parts[0]
    flipped = wire[:-5] + ("A" if wire[-5] != "A" else "B") + wire[-4:]
    with pytest.raises(TelecloakError):
        b.open(flipped)
    with pytest.raises(TelecloakError):
        b.open("tc1.!!!")
    with pytest.raises(TelecloakError):
        b.open("hello")


def test_replay_detected():
    a, b = pair()
    sealed, msg = roundtrip(a, b, {"text": "once"})
    seen = Seen()
    assert seen.add(msg.msg_id) is True
    _, again = roundtrip(a, b, {"text": "once"})   # a fresh message gets a fresh id
    assert seen.add(again.msg_id) is True
    replay = Reassembler().add(b.open(sealed.parts[0]))
    assert seen.add(replay.msg_id) is False


def test_seen_forgets_after_keep():
    s = Seen(keep=10)
    assert s.add("x", now=0)
    assert not s.add("x", now=5)
    assert s.add("x", now=100)


def test_reassembler_state_is_json_and_survives_reload():
    import json
    a, b = pair()
    sealed = a.seal({"text": "y" * 7000})
    state = {}
    for w in sealed.parts[:-1]:
        assert Reassembler(state).add(b.open(w)) is None
        state = json.loads(json.dumps(state))
    assert Reassembler(state).add(b.open(sealed.parts[-1])).body["text"] == "y" * 7000


def test_keys_and_fingerprint():
    k = new_psk()
    assert fingerprint(load_psk(k)) == fingerprint(load_psk(k))
    assert fingerprint(load_psk(k)) != fingerprint(load_psk(new_psk()))
    for bad in ["", "not base64!", "AAAA"]:
        with pytest.raises(TelecloakError):
            load_psk(bad)


def test_open_part_rejects_bad_numbering():
    # a well-encrypted part whose header says index >= count is refused
    import os
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from telecloak.core import AAD, HEADER, PREFIX, _b64e
    key = os.urandom(32)
    nonce = os.urandom(12)
    pt = HEADER.pack(os.urandom(8), 0, 3, 2) + b"{}"
    with pytest.raises(TelecloakError):
        open_part(key, PREFIX + _b64e(nonce + AESGCM(key).encrypt(nonce, pt, AAD)))
