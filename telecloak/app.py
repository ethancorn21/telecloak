"""telecloak desktop app: read and write encrypted Telegram chats from your own account.

Telegram carries only "tc1." ciphertext; this app encrypts what you type and decrypts what arrives. It logs in as your
Telegram account through MTProto (Telethon), the protocol the official apps use, so messages come from you, not a bot.

Chats ("peers") are either a person who runs telecloak too, or the lab bot (the AI lab's relay: requests from the
agents arrive here; answers, messages and loop commands go back).

Everything secret lives in the config dir (mode 0700), never in the repo:
  config.json        api_id / api_hash (my.telegram.org) and the chat list
  keys/<name>.key    one pre-shared key per chat (0600)
  telecloak.session  the Telegram login. Anyone holding this file can read all your chats: it is a logged-in device
                     (Telegram Settings > Devices shows it; terminate it there if the file ever leaks).
TELECLOAK_HOME overrides the config dir (a second profile, or a test account).

Threads: Tk runs in the main thread; Telethon runs an asyncio loop in a background thread. The UI hands work to the
loop with run_coroutine_threadsafe; the loop hands UI updates back through a queue the UI polls.
"""
import asyncio
import datetime as dt
import fcntl
import json
import os
import queue
import re
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, scrolledtext, simpledialog, ttk

from telethon import TelegramClient, events
from telethon.errors import PhoneCodeInvalidError, SessionPasswordNeededError

from .core import Channel, Reassembler, TelecloakError, fingerprint, is_wire, load_psk, new_psk

if os.environ.get("TELECLOAK_HOME"):
    HOME = Path(os.environ["TELECLOAK_HOME"]).expanduser()
elif sys.platform == "darwin":
    HOME = Path.home() / "Library" / "Application Support" / "telecloak"
else:
    HOME = Path.home() / ".config" / "telecloak"
CONFIG = HOME / "config.json"
KEYS = HOME / "keys"
SESSION = HOME / "telecloak"          # Telethon appends .session
HISTORY = 200                         # messages loaded per chat at start
NAME_RE = re.compile(r"^[A-Za-z0-9 ._-]{1,40}$")
# Text from the other side is shown as plain text only: control characters and bidi overrides are removed (they can
# disguise what a message says), and nothing is ever turned into a link or run.
UNSAFE = re.compile("[\u0000-\u0008\u000b-\u001f\u007f-\u009f‪-‮⁦-⁩]")


def clean(s) -> str:
    return UNSAFE.sub("", str(s))


def write_private(path: Path, data: str):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(data)
    os.chmod(path, 0o600)


def load_config() -> dict:
    HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(HOME, 0o700)
    if CONFIG.exists():
        return json.loads(CONFIG.read_text())
    return {"api_id": None, "api_hash": None, "peers": []}


def save_config(cfg: dict):
    write_private(CONFIG, json.dumps(cfg, indent=2))


def key_path(name: str) -> Path:
    return KEYS / (re.sub(r"[^A-Za-z0-9._-]", "_", name) + ".key")


class Peer:
    def __init__(self, cfg: dict):
        self.name = cfg["name"]
        self.kind = cfg["kind"]              # "bot" (the lab relay) or "person"
        self.target = cfg["target"]          # @username (or phone number) on Telegram
        self.psk = load_psk(key_path(self.name).read_text())
        self.entity = None
        self.id = None
        self.channel = None
        self.re_in, self.re_out = Reassembler(), Reassembler()
        self.shown = set()                   # message ids already on screen (history + live + own sends)


class Backend(threading.Thread):
    """Telegram side. Everything here runs on the background asyncio loop."""

    def __init__(self, ui, cfg):
        super().__init__(daemon=True)
        self.ui, self.cfg = ui, cfg
        self.loop = asyncio.new_event_loop()
        self.client = None
        self.me = None
        self.by_id, self.by_name = {}, {}

    def run(self):
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self.main())
        except Exception as e:  # noqa: BLE001 - shown to the user, the thread ends
            self.ui.later(self.ui.set_status, f"Disconnected: {e}")

    def submit(self, coro):
        return asyncio.run_coroutine_threadsafe(coro, self.loop)

    async def main(self):
        self.client = TelegramClient(str(SESSION), int(self.cfg["api_id"]), self.cfg["api_hash"])
        self.client.parse_mode = None        # send text exactly: markdown parsing would eat "__" in the ciphertext
        self.ui.later(self.ui.set_status, "Connecting to Telegram...")
        await self.client.connect()
        if not await self.client.is_user_authorized():
            await self.login()
        for f in HOME.glob("telecloak.session*"):
            os.chmod(f, 0o600)
        self.me = await self.client.get_me()
        who = f"@{self.me.username}" if self.me.username else self.me.first_name
        self.ui.later(self.ui.set_status, f"Online as {who}")
        self.client.add_event_handler(self.on_message, events.NewMessage())
        for p in self.cfg["peers"]:
            await self.add_peer(p)
        await self.client.run_until_disconnected()

    async def login(self):
        phone = self.ui.ask("Telegram login", "Your phone number, international format (+1...):")
        if not phone:
            raise RuntimeError("login cancelled")
        await self.client.send_code_request(phone)
        while True:
            code = self.ui.ask("Telegram login", "The login code Telegram just sent you (in the Telegram app):")
            if not code:
                raise RuntimeError("login cancelled")
            try:
                await self.client.sign_in(phone=phone, code=code.strip())
                return
            except PhoneCodeInvalidError:
                self.ui.later(self.ui.set_status, "Wrong code, try again")
            except SessionPasswordNeededError:
                pw = self.ui.ask("Telegram login", "Your Telegram two-step verification password:", secret=True)
                await self.client.sign_in(password=pw)
                return

    async def add_peer(self, cfg: dict):
        try:
            peer = Peer(cfg)
            peer.entity = await self.client.get_entity(peer.target)
            peer.id = peer.entity.id
            if peer.id in self.by_id:
                raise ValueError(f"\"{self.by_id[peer.id].name}\" is already this Telegram account; remove one of them")
            # The chat type comes from Telegram, not from the user: a bot account is the lab relay, anyone else a person.
            peer.kind = "bot" if getattr(peer.entity, "bot", False) else "person"
            peer.channel = Channel(peer.psk, self.me.id, peer.id)
        except Exception as e:  # noqa: BLE001
            self.ui.later(self.ui.warn, cfg["name"], f"cannot open this chat: {e}")
            return
        self.by_id[peer.id], self.by_name[peer.name] = peer, peer
        # queued before the history below, so every message is shown with the right chat type
        self.ui.later(self.ui.peer_ready, peer.name, fingerprint(peer.psk), peer.kind)
        msgs = await self.client.get_messages(peer.entity, limit=HISTORY)
        for m in reversed(msgs):
            self.handle(peer, m)

    async def remove_peer(self, name: str):
        peer = self.by_name.pop(name, None)
        if peer:
            self.by_id.pop(peer.id, None)

    async def on_message(self, event):
        peer = self.by_id.get(event.chat_id)
        if peer:
            self.handle(peer, event.message)

    def handle(self, peer: Peer, msg):
        text = msg.message or ""
        when = msg.date.timestamp() if msg.date else None
        if not is_wire(text):
            if text.strip():
                self.ui.later(self.ui.show_plain, peer.name, msg.out, when, text)
            return
        try:
            part = peer.channel.open(text, outgoing=msg.out)
            m = (peer.re_out if msg.out else peer.re_in).add(part)
        except TelecloakError as e:
            self.ui.later(self.ui.warn, peer.name, f"rejected a message: {e}")
            return
        if m is None or m.msg_id in peer.shown:
            return
        peer.shown.add(m.msg_id)
        self.ui.later(self.ui.show, peer.name, msg.out, m.ts, m.body)

    async def send(self, name: str, body: dict):
        peer = self.by_name.get(name)
        if not peer:
            self.ui.later(self.ui.warn, name, "not connected to this chat")
            return
        try:
            sealed = peer.channel.seal(body)
            peer.shown.add(sealed.msg_id)
            for wire in sealed.parts:
                await self.client.send_message(peer.entity, wire, link_preview=False)
            self.ui.later(self.ui.show, name, True, sealed.ts, body)
        except Exception as e:  # noqa: BLE001
            self.ui.later(self.ui.warn, name, f"not sent: {e}")


class App:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.q = queue.Queue()
        self.cfg = load_config()
        self.backend = None
        self.entries = {}       # peer name -> list of (tag, header, text)
        self.fps = {}           # peer name -> key fingerprint
        self.projects = {}      # bot peer name -> projects seen, in order
        self.open_asks = {}     # bot peer name -> {project: [request numbers]}
        self.offered = set()    # (peer, project, request) already pre-selected as the reply target
        self.current = tk.StringVar()
        self.build()
        self.root.after(100, self.pump)
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        self.root.after(200, self.start)

    # ---- cross-thread plumbing -------------------------------------------------------------------------------------
    def later(self, fn, *args):
        """Run fn(*args) on the Tk thread (callable from any thread)."""
        self.q.put((fn, args))

    def pump(self):
        try:
            while True:
                fn, args = self.q.get_nowait()
                fn(*args)
        except queue.Empty:
            pass
        self.root.after(100, self.pump)

    def ask(self, title, prompt, secret=False):
        """Blocking question from the background thread, answered in a dialog on the Tk thread."""
        done, box = threading.Event(), {}

        def show():
            box["v"] = simpledialog.askstring(title, prompt, parent=self.root, show="*" if secret else None)
            done.set()
        self.later(show)
        done.wait()
        return box.get("v")

    # ---- layout ----------------------------------------------------------------------------------------------------
    def build(self):
        r = self.root
        r.title("telecloak")
        r.geometry("820x640")
        top = ttk.Frame(r, padding=(8, 8, 8, 0))
        top.pack(fill="x")
        ttk.Label(top, text="Chat:").pack(side="left")
        self.peer_box = ttk.Combobox(top, textvariable=self.current, state="readonly", width=24)
        self.peer_box.pack(side="left", padx=6)
        self.peer_box.bind("<<ComboboxSelected>>", lambda _e: self.render())
        ttk.Button(top, text="Add chat...", command=self.add_chat).pack(side="left")
        ttk.Button(top, text="Remove chat", command=self.remove_chat).pack(side="left", padx=(4, 0))
        self.fp_label = ttk.Label(top, text="", foreground="gray")
        self.fp_label.pack(side="right")

        # Bottom-up: status line, input row, bot controls (only for the lab bot), then the log takes what is left.
        self.status = ttk.Label(r, text="", foreground="gray", padding=(8, 2, 8, 12))
        self.status.pack(fill="x", side="bottom")
        bottom = ttk.Frame(r, padding=(8, 4, 8, 4))
        bottom.pack(fill="x", side="bottom")
        # a visible frame: in macOS dark mode a bare Text has the window's colour and no border
        self.text = tk.Text(bottom, height=4, wrap="word", font=("Menlo", 12), padx=6, pady=4, borderwidth=0,
                            highlightthickness=1, highlightbackground="gray50", highlightcolor="#3b82f6")
        self.text.pack(side="left", fill="x", expand=True)
        self.text.bind("<Command-Return>", lambda _e: (self.send(), "break")[1])
        self.text.bind("<Control-Return>", lambda _e: (self.send(), "break")[1])
        side = ttk.Frame(bottom)
        side.pack(side="left", padx=(8, 0))
        ttk.Button(side, text="Send", command=self.send).pack()
        ttk.Label(side, text="Cmd+Enter", foreground="gray").pack()

        self.log = scrolledtext.ScrolledText(r, wrap="word", state="disabled", font=("Menlo", 12), padx=8, pady=6,
                                             height=10)
        self.log.pack(fill="both", expand=True, padx=8, pady=8)
        self.log.tag_config("in_head", foreground="#1f6f43", font=("Menlo", 11, "bold"))
        self.log.tag_config("out_head", foreground="#1f4f8f", font=("Menlo", 11, "bold"))
        self.log.tag_config("warn", foreground="#b03030")
        self.log.tag_config("plain", foreground="#a06000")

        self.bot_bar = ttk.Frame(r, padding=(8, 0))
        ttk.Label(self.bot_bar, text="Project:").pack(side="left")
        self.project = ttk.Combobox(self.bot_bar, width=18)
        self.project.pack(side="left", padx=(4, 10))
        self.project.bind("<<ComboboxSelected>>", lambda _e: self.refresh_targets())
        self.project.bind("<KeyRelease>", lambda _e: self.refresh_targets())
        ttk.Label(self.bot_bar, text="Send as:").pack(side="left")
        self.target = ttk.Combobox(self.bot_bar, state="readonly", width=24)
        self.target.pack(side="left", padx=(4, 10))
        for label, cmd in (("Status", "status"), ("Start", "start"), ("Stop", "stop"), ("Stop now", "stop-now")):
            ttk.Button(self.bot_bar, text=label, command=lambda c=cmd: self.command(c)).pack(side="left", padx=2)

    def start(self):
        if not self.cfg.get("api_id") or not self.cfg.get("api_hash"):
            messagebox.showinfo("telecloak setup",
                                "telecloak logs in as your own Telegram account. It needs an API id for that:\n\n"
                                "1. Open https://my.telegram.org and log in\n"
                                "2. API development tools: create an app (any name)\n"
                                "3. Copy its api_id and api_hash into the next two boxes")
            api_id = simpledialog.askstring("telecloak setup", "api_id (a number):", parent=self.root)
            api_hash = simpledialog.askstring("telecloak setup", "api_hash:", parent=self.root, show="*")
            if not api_id or not api_id.strip().isdigit() or not api_hash:
                messagebox.showerror("telecloak", "Both are needed. Start telecloak again to retry.")
                self.root.destroy()
                return
            self.cfg["api_id"], self.cfg["api_hash"] = int(api_id.strip()), api_hash.strip()
            save_config(self.cfg)
        names = [p["name"] for p in self.cfg["peers"]]
        self.peer_box["values"] = names
        if names:
            self.current.set(names[0])
        self.render()
        self.backend = Backend(self, self.cfg)
        self.backend.start()

    def quit(self):
        if self.backend and self.backend.client:
            try:
                self.backend.submit(self.backend.client.disconnect()).result(timeout=3)
            except Exception:  # noqa: BLE001
                pass
        self.root.destroy()

    # ---- showing messages ------------------------------------------------------------------------------------------
    def set_status(self, s):
        self.status.config(text=s)

    def peer_ready(self, name, fp, kind):
        self.fps[name] = fp
        p = next((p for p in self.cfg["peers"] if p["name"] == name), None)
        if p and p["kind"] != kind:
            p["kind"] = kind
            save_config(self.cfg)
            self.entries.pop(name, None)     # anything shown so far used the wrong type; the history follows
        if name == self.current.get():
            self.render()

    def kind(self, name):
        return next((p["kind"] for p in self.cfg["peers"] if p["name"] == name), "person")

    @staticmethod
    def stamp(ts):
        if ts is None:
            return "--:--"
        t = dt.datetime.fromtimestamp(ts)
        return t.strftime("%H:%M") if t.date() == dt.date.today() else t.strftime("%b %d %H:%M")

    def add_entry(self, name, tag, header, text):
        self.entries.setdefault(name, []).append((tag, header, text))
        if name == self.current.get():
            self.append(tag, header, text)

    def append(self, tag, header, text):
        self.log.config(state="normal")
        self.log.insert("end", header + "\n", tag)
        if text:
            self.log.insert("end", text.rstrip() + "\n\n", "warn" if tag == "warn" else ("plain" if tag == "plain" else ()))
        else:
            self.log.insert("end", "\n")
        self.log.config(state="disabled")
        self.log.see("end")

    def warn(self, name, text):
        self.add_entry(name, "warn", f"[{self.stamp(dt.datetime.now().timestamp())}] telecloak", clean(text))

    def show_plain(self, name, out, ts, text):
        who = "you" if out else name
        self.add_entry(name, "plain", f"[{self.stamp(ts)}] {who} (NOT ENCRYPTED)", clean(text))

    def show(self, name, out, ts, body):
        k = body.get("kind")
        project = clean(body.get("project", ""))
        text = clean(body.get("text", ""))
        if self.kind(name) != "bot":
            self.add_entry(name, "out_head" if out else "in_head", f"[{self.stamp(ts)}] {'you' if out else name}", text)
            return
        asks = self.open_asks.setdefault(name, {})
        if project and project not in self.projects.setdefault(name, []):
            self.projects[name].append(project)
        if out:
            if k == "answer":
                head = f"you -> {project}: answer to request {body.get('ask')}"
                self._close_ask(name, project, body.get("ask"))
            elif k == "command":
                head, text = f"you -> command: {body.get('command')} {project}".rstrip(), ""
            else:
                head = f"you -> {project}"
            self.add_entry(name, "out_head", f"[{self.stamp(ts)}] {head}", text)
        else:
            if k == "ask":
                n = clean(body.get("ask", ""))
                head = f"{project} asks (request {n})"
                if n and n not in asks.setdefault(project, []):
                    asks[project].append(n)
            elif k == "ring":
                if project and isinstance(body.get("asks"), list):
                    # a ring lists the project's open requests at that moment: drop ones answered elsewhere (agent-talk)
                    asks[project] = [a for a in asks.get(project, []) if a in body["asks"]] + \
                                    [a for a in body["asks"] if a not in asks.get(project, [])]
                waiting = ", ".join(clean(a) for a in body.get("asks", []))
                head = f"{project}: waiting on request(s) {waiting}" if waiting else (project or "lab bot")
            else:
                head = project or "lab bot"
            for n in body.get("answered", []) if isinstance(body.get("answered"), list) else []:
                self._close_ask(name, project, n)
            self.add_entry(name, "in_head", f"[{self.stamp(ts)}] {head}", text)
        if name == self.current.get():
            self.refresh_bot_bar()

    def _close_ask(self, name, project, n):
        lst = self.open_asks.get(name, {}).get(project, [])
        if n in lst:
            lst.remove(n)

    def render(self):
        name = self.current.get()
        self.log.config(state="normal")
        self.log.delete("1.0", "end")
        self.log.config(state="disabled")
        for e in self.entries.get(name, []):
            self.append(*e)
        fp = self.fps.get(name)
        self.fp_label.config(text=f"key fingerprint {fp}" if fp else "")
        if self.kind(name) == "bot":
            self.bot_bar.pack(fill="x", side="bottom", before=self.log)
            self.refresh_bot_bar()
        else:
            self.bot_bar.pack_forget()

    def refresh_bot_bar(self):
        name = self.current.get()
        projects = self.projects.get(name, [])
        self.project["values"] = projects
        if not self.project.get() and projects:
            self.project.set(projects[-1])
        self.refresh_targets()

    def refresh_targets(self):
        name, project = self.current.get(), self.project.get().strip()
        asks = self.open_asks.get(name, {}).get(project, [])
        values = ["Message to the agent"] + [f"Answer to request {n}" for n in asks]
        self.target["values"] = values
        newest = (name, project, asks[-1]) if asks else None
        if newest and newest not in self.offered:
            self.offered.add(newest)             # a new open request: answering it is the likely next step (once)
            self.target.set(values[-1])
        elif self.target.get() not in values:
            self.target.set(values[0])

    # ---- sending ---------------------------------------------------------------------------------------------------
    def send(self):
        name = self.current.get()
        text = self.text.get("1.0", "end").strip()
        if not name or not text or not self.backend:
            return
        if self.kind(name) == "bot":
            project = self.project.get().strip()
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", project):
                messagebox.showwarning("telecloak", "Pick or type the project this is for.")
                return
            t = self.target.get()
            if t.startswith("Answer to request "):
                body = {"kind": "answer", "project": project, "ask": t.rsplit(" ", 1)[1], "text": text}
            else:
                body = {"kind": "message", "project": project, "text": text}
        else:
            body = {"kind": "chat", "text": text}
        self.text.delete("1.0", "end")
        self.backend.submit(self.backend.send(name, body))

    def command(self, cmd):
        name = self.current.get()
        project = self.project.get().strip()
        if cmd != "status" and not project:
            messagebox.showwarning("telecloak", "Pick or type the project first.")
            return
        if project and not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", project):
            messagebox.showwarning("telecloak", "That is not a project name.")
            return
        if cmd == "stop-now" and not messagebox.askyesno(
                "telecloak", f"Stop {project} now? The running agent session is killed mid-step "
                             "(its uncommitted work is saved when the loop starts again)."):
            return
        body = {"kind": "command", "command": cmd}
        if project:
            body["project"] = project
        self.backend.submit(self.backend.send(name, body))

    # ---- removing a chat -------------------------------------------------------------------------------------------
    def remove_chat(self):
        name = self.current.get()
        if not name:
            return
        if not messagebox.askyesno(
                "Remove chat", f"Remove \"{name}\" from telecloak?\n\nIts key is deleted from this Mac, so its messages "
                               "can no longer be read here. The Telegram conversation itself stays (as ciphertext). "
                               "To chat again, add it with the same key, or agree on a new one.", icon="warning"):
            return
        self.cfg["peers"] = [p for p in self.cfg["peers"] if p["name"] != name]
        save_config(self.cfg)
        try:
            key_path(name).unlink()
        except FileNotFoundError:
            pass
        for d in (self.entries, self.fps, self.projects, self.open_asks):
            d.pop(name, None)
        self.offered = {o for o in self.offered if o[0] != name}
        if self.backend:
            self.backend.submit(self.backend.remove_peer(name))
        names = [p["name"] for p in self.cfg["peers"]]
        self.peer_box["values"] = names
        self.current.set(names[0] if names else "")
        self.render()

    # ---- adding a chat ---------------------------------------------------------------------------------------------
    def add_chat(self):
        w = tk.Toplevel(self.root)
        w.title("Add chat")
        w.transient(self.root)
        f = ttk.Frame(w, padding=12)
        f.pack(fill="both", expand=True)
        name, target, key = tk.StringVar(), tk.StringVar(), tk.StringVar()
        ttk.Label(f, text="Name (just a label):").grid(row=0, column=0, sticky="w")
        ttk.Entry(f, textvariable=name, width=36).grid(row=0, column=1, columnspan=3, sticky="we", pady=2)
        ttk.Label(f, text="Telegram @username:").grid(row=2, column=0, sticky="w")
        ttk.Entry(f, textvariable=target, width=36).grid(row=2, column=1, columnspan=3, sticky="we", pady=2)
        ttk.Label(f, text="A bot account becomes the lab bot chat; anyone else a person chat.",
                  foreground="gray").grid(row=1, column=1, columnspan=3, sticky="w")
        ttk.Label(f, text="Shared key:").grid(row=3, column=0, sticky="w")
        ttk.Entry(f, textvariable=key, width=48, show="*").grid(row=3, column=1, columnspan=3, sticky="we", pady=2)
        fp = ttk.Label(f, text="", foreground="gray")
        fp.grid(row=4, column=1, columnspan=3, sticky="w")

        def update_fp(*_):
            try:
                fp.config(text=f"fingerprint {fingerprint(load_psk(key.get()))}")
            except TelecloakError:
                fp.config(text="")
        key.trace_add("write", update_fp)

        def generate():
            key.set(new_psk())

        def copy():
            self.root.clipboard_clear()
            self.root.clipboard_append(key.get())
            messagebox.showinfo("telecloak", "Key copied. Paste it where it needs to go (the other person's "
                                "telecloak, or the lab's telecloak-setup), then copy something else so it does not "
                                "stay on the clipboard. Share it with a person in person or over another app you trust, "
                                "never over Telegram.", parent=w)
        btns = ttk.Frame(f)
        btns.grid(row=5, column=1, columnspan=3, sticky="w", pady=(4, 8))
        ttk.Button(btns, text="Generate new key", command=generate).pack(side="left")
        ttk.Button(btns, text="Copy key", command=copy).pack(side="left", padx=6)

        def save():
            n, t = name.get().strip(), target.get().strip()
            if not NAME_RE.fullmatch(n) or any(p["name"] == n for p in self.cfg["peers"]):
                messagebox.showerror("telecloak", "Pick a new name (letters, digits, space . _ -).", parent=w)
                return
            if not t:
                messagebox.showerror("telecloak", "Enter their Telegram @username.", parent=w)
                return
            same = next((p["name"] for p in self.cfg["peers"] if p["target"].lstrip("@").lower() == t.lstrip("@").lower()), None)
            if same:
                messagebox.showerror("telecloak", f"\"{same}\" is already this account. One chat per account: "
                                     "remove that one first to change its key.", parent=w)
                return
            try:
                load_psk(key.get())
            except TelecloakError as e:
                messagebox.showerror("telecloak", f"Key: {e}", parent=w)
                return
            write_private(key_path(n), key.get().strip() + "\n")
            p = {"name": n, "kind": "person", "target": t}     # corrected from Telegram once the chat opens
            self.cfg["peers"].append(p)
            save_config(self.cfg)
            self.peer_box["values"] = [x["name"] for x in self.cfg["peers"]]
            self.current.set(n)
            self.render()
            if self.backend and self.backend.me:
                self.backend.submit(self.backend.add_peer(p))
            w.destroy()
        ttk.Button(f, text="Save", command=save).grid(row=6, column=3, sticky="e")


def main():
    # One window at a time: two would share the Telegram session file (SQLite) and fight over it.
    HOME.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = open(HOME / "app.lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        sys.exit("telecloak is already running (look for its window).")
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
