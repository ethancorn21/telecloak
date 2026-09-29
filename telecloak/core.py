"""telecloak core: pre-shared-key encryption for messages carried over Telegram.

Telegram only ever sees ciphertext. Both ends hold the same 32-byte pre-shared key (PSK), exchanged outside Telegram.

Keys: each direction of a conversation gets its own key, derived with HKDF from the PSK and the two Telegram user ids
("<sender>-><receiver>"). A message can then only be opened by the side it was sent to: Telegram cannot bounce your
own message back to you and have it accepted as the other side's (a reflection attack).

Wire format (one Telegram text message): "tc1." + base64url(nonce || AES-256-GCM ciphertext+tag), no padding.
AES-GCM is an AEAD cipher: it encrypts and authenticates, so any change to a message makes it fail to open.
Inside the ciphertext: a fixed header (message id 8 bytes, unix time uint64, part index uint8, part count uint8), then
a slice of the message body (UTF-8 JSON). Telegram caps a text message at 4096 characters, so a long body is split
across several messages and put back together by message id. The header is encrypted too, so Telegram sees neither
the ids nor the timestamps.

Replays (Telegram delivering the same valid message again) are caught by remembering accepted message ids (Seen);
how old a message may be is the receiver's policy.
"""
import base64
import binascii
import json
import os
import struct
import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = "tc1."
AAD = b"telecloak v1"                 # authenticated but not encrypted: binds every ciphertext to this format version
HEADER = struct.Struct(">8sQBB")      # message id, unix time, part index, part count
NONCE = 12
TAG = 16
PIECE = 2900                          # body bytes per part: the wire text stays under Telegram's 4096 characters
MAX_BODY = 64 * 1024
TELEGRAM_LIMIT = 4096


class TelecloakError(Exception):
    pass


def new_psk() -> str:
    """A fresh random key, base64 (what the key files and the setup prompts hold)."""
    return base64.b64encode(os.urandom(32)).decode()


def load_psk(text: str) -> bytes:
    try:
        raw = base64.b64decode(text.strip(), validate=True)
    except (binascii.Error, ValueError):
        raise TelecloakError("the key is not valid base64") from None
    if len(raw) != 32:
        raise TelecloakError(f"the key must be 32 bytes, this one is {len(raw)}")
    return raw


def _hkdf(psk: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=b"telecloak", info=info).derive(psk)


def fingerprint(psk: bytes) -> str:
    """Short code both sides can compare to confirm they hold the same key, without revealing it (one-way)."""
    h = _hkdf(psk, b"fingerprint")[:6].hex()
    return "-".join(h[i:i + 4] for i in range(0, 12, 4))


def direction_key(psk: bytes, sender_id: int, receiver_id: int) -> bytes:
    return _hkdf(psk, f"v1 {int(sender_id)}->{int(receiver_id)}".encode())


def is_wire(text) -> bool:
    return isinstance(text, str) and text.startswith(PREFIX)


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


@dataclass
class Sealed:
    msg_id: str        # hex
    ts: int
    parts: list        # wire strings, one Telegram message each, in order


@dataclass
class Part:
    msg_id: str
    ts: int
    index: int
    count: int
    piece: bytes


@dataclass
class Message:
    msg_id: str
    ts: int
    body: dict


def seal(key: bytes, body: dict, now: float | None = None) -> Sealed:
    data = json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
    if len(data) > MAX_BODY:
        raise TelecloakError(f"message too long ({len(data)} bytes, at most {MAX_BODY})")
    pieces = [data[i:i + PIECE] for i in range(0, len(data), PIECE)] or [b""]
    msg_id = os.urandom(8)
    ts = int(time.time() if now is None else now)
    aes = AESGCM(key)
    parts = []
    for i, piece in enumerate(pieces):
        nonce = os.urandom(NONCE)   # random 96-bit nonce per part: never reused under one key in practice
        pt = HEADER.pack(msg_id, ts, i, len(pieces)) + piece
        parts.append(PREFIX + _b64e(nonce + aes.encrypt(nonce, pt, AAD)))
    return Sealed(msg_id.hex(), ts, parts)


def open_part(key: bytes, text: str) -> Part:
    if not is_wire(text):
        raise TelecloakError("not a telecloak message")
    try:
        raw = _b64d(text[len(PREFIX):].strip())
    except (binascii.Error, ValueError):
        raise TelecloakError("damaged message (not base64)") from None
    if len(raw) < NONCE + HEADER.size + TAG:
        raise TelecloakError("damaged message (too short)")
    try:
        pt = AESGCM(key).decrypt(raw[:NONCE], raw[NONCE:], AAD)
    except InvalidTag:
        raise TelecloakError("does not open with this key (wrong key, wrong sender, or changed in transit)") from None
    mid, ts, index, count = HEADER.unpack_from(pt)
    if count == 0 or index >= count:
        raise TelecloakError("bad part numbering")
    return Part(mid.hex(), ts, index, count, pt[HEADER.size:])


class Channel:
    """One conversation between two Telegram accounts (me, peer) that share a PSK."""

    def __init__(self, psk: bytes, me: int, peer: int):
        self.send_key = direction_key(psk, me, peer)
        self.recv_key = direction_key(psk, peer, me)

    def seal(self, body: dict, now: float | None = None) -> Sealed:
        return seal(self.send_key, body, now)

    def open(self, text: str, outgoing: bool = False) -> Part:
        """outgoing=True opens a message this side sent (e.g. its own history)."""
        return open_part(self.send_key if outgoing else self.recv_key, text)


class Reassembler:
    """Puts split messages back together. add() returns the Message once all its parts are in, else None.
    state is plain JSON (parts as base64), so a stateless caller can keep it in a file between runs."""

    def __init__(self, state: dict | None = None, ttl: int = 3600):
        self.state = state if state is not None else {}
        self.ttl = ttl

    def add(self, part: Part, now: float | None = None) -> Message | None:
        now = time.time() if now is None else now
        for mid in [m for m, e in self.state.items() if now - e["t"] > self.ttl]:
            del self.state[mid]
        if part.count == 1:
            return _message(part.msg_id, part.ts, part.piece)
        e = self.state.setdefault(part.msg_id, {"ts": part.ts, "n": part.count, "t": now, "parts": {}})
        if e["n"] != part.count or e["ts"] != part.ts:
            raise TelecloakError("parts of one message disagree")
        e["parts"][str(part.index)] = _b64e(part.piece)
        if len(e["parts"]) < e["n"]:
            return None
        del self.state[part.msg_id]
        return _message(part.msg_id, part.ts, b"".join(_b64d(e["parts"][str(i)]) for i in range(e["n"])))


def _message(msg_id: str, ts: int, data: bytes) -> Message:
    try:
        body = json.loads(data.decode())
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TelecloakError("message body is not JSON") from None
    if not isinstance(body, dict):
        raise TelecloakError("message body is not an object")
    return Message(msg_id, ts, body)


class Seen:
    """Ids of accepted messages, to reject replays. Kept `keep` seconds: the receiver must also refuse messages older
    than that, or a replay could slip in once its id has been forgotten."""

    def __init__(self, state: dict | None = None, keep: int = 7 * 86400):
        self.state = state if state is not None else {}
        self.keep = keep

    def add(self, msg_id: str, now: float | None = None) -> bool:
        """True if new (and remembers it), False if already seen."""
        now = time.time() if now is None else now
        for mid in [m for m, t in self.state.items() if now - t > self.keep]:
            del self.state[mid]
        if msg_id in self.state:
            return False
        self.state[msg_id] = now
        return True
