# telecloak

End-to-end encrypted messages over Telegram, with a pre-shared key. Telegram only ever carries `tc1.` ciphertext; the
telecloak desktop app encrypts what you type and decrypts what arrives. Messages are sent from your own Telegram account.

Two kinds of chat:

- **A person** who also runs telecloak. You share a key with them once, in person or over an app you already trust.
- **The lab bot:** the AI lab's relay ([Local-AI-Lab](https://github.com/ethancorn21/Local-AI-Lab), `server/doorbell/`).
  The coding agents' requests arrive here. You answer them, message a project, or start, stop and check its loop.

It follows on from [DEMP](../DEMP), which tried the same over Discord and failed because the plaintext went through
Discord's own client. telecloak encrypts outside Telegram, so the service is only the transport.

## Run it

Once:

```sh
brew install python-tk@3.14            # Tk for Homebrew's Python (macOS)
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt && .venv/bin/pip install -e .
ln -s "$PWD/bin/telecloak" ~/.local/bin/telecloak     # any directory on your PATH
```

Then, from any terminal:

```sh
telecloak
```

It starts in the background and gives the prompt back; closing the terminal does not close it (quit from its window).
Only one copy runs at a time. Errors go to `~/Library/Logs/telecloak.log`.

The first start asks for an `api_id` and `api_hash`. Get them from https://my.telegram.org, under API development tools
(create any app). Next it asks for your phone number, the login code Telegram sends, and your two-step password if you
have one.

**Add a chat:** click Add chat and give it a name and their Telegram @username. The type comes from Telegram: a bot
account becomes the lab bot chat (with the project controls), anyone else a person chat. Then either click Generate
new key and copy it to the other side, or paste the key they generated. Both sides show the same **key fingerprint**
when the keys match. Compare the fingerprints over a channel other than Telegram. One chat per Telegram account; to
change a chat's key, remove the chat and add it again.

**Remove a chat:** click Remove chat. Its key is deleted from this Mac; the Telegram conversation stays (ciphertext
only), readable again only with the same key.

**Lab bot:** after generating the key, run `ssh -t <ai box> sudo telecloak-setup` in your own terminal and paste the
key (typing is hidden). It prints the fingerprint and sends an encrypted test ping, which shows up in the app.

## How it works

`telecloak/core.py` is the whole protocol:

| Piece | What | Why |
|---|---|---|
| Pre-shared key | 32 random bytes per chat | Nothing to trust on Telegram's side, no key exchange over it |
| Direction keys | HKDF-SHA256(key, `"v1 <sender id>-><receiver id>"`) | Each direction has its own key. If Telegram bounces your own message back to you, it doesn't open as the other side's (reflection) |
| AES-256-GCM | Random 96-bit nonce per message | Authenticated encryption: a changed message fails to open instead of decrypting to garbage |
| Encrypted header | Message id, timestamp, part i of n | Ids let the receiver reject replays. Timestamps let it refuse stale messages. Parts get past Telegram's 4096-character limit. The header is encrypted, so Telegram sees none of it |
| Wire | `tc1.` + base64url(nonce + ciphertext) | Plain text that survives any Telegram client. Sent with no markdown parsing, so `_` and `-` stay intact |

## Threat model

- **Telegram, or anyone on the network:** sees who talks to whom, when, and roughly how long each message is. It can't
  read messages, change them, forge them, replay them to the lab, or reflect them. It can delay or drop messages.
- **Someone who takes over your Telegram account:** can't send commands to the lab. The relay also requires the
  key, and the key never leaves your Mac or the AI box.
- **Your Mac:** holds the keys and the Telegram session (`~/Library/Application Support/telecloak`, mode 0700). The
  `telecloak.session` file is a logged-in Telegram device: anyone who copies it can read all your chats, telecloak or
  not. If that ever happens, end the session in Telegram, Settings > Devices.
- **The lab agents:** can decide what text you see (a request from a prompt-injected agent could show a malicious
  command), but never touch keys. The app shows plain text only: no links, and control and bidi characters are
  stripped. Read any command in a request before you run it.
- **Not provided:** forward secrecy. If a key leaks, everything sent with it can be read. Rotate it by generating a new
  key on both sides. A ratchet (Signal-style, new keys per message) is the next step up, and it is on the DEMP todo list.

## Tests

```sh
.venv/bin/python -m pytest -q
```

The lab side (relay, puller, `ring-doorbell`) has its own tests in Local-AI-Lab, `analysis/tests/test_telecloak_lab.py`.
