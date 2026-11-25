"""Rabit: encrypted peer-to-peer chat for a local network."""

from __future__ import annotations

import queue
import socket
import tkinter as tk
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from rabit_network import NetworkClient, derive_room_key, load_peer_id


class RabitApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Rabit")
        self.root.geometry("1020x700")
        self.root.minsize(760, 520)
        self.root.configure(bg="#10141c")
        self.network: NetworkClient | None = None
        self.peers: dict[str, dict] = {}
        self.history: dict[str, list[tuple[str, str, str]]] = {"group": []}
        self.current_conversation = "group"
        self.contact_ids: list[str] = []
        self.status_var = tk.StringVar(value="Create or join a room on your local network.")
        self._configure_style()
        self._show_connect_screen()
        self.root.protocol("WM_DELETE_WINDOW", self._close)

    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#10141c")
        style.configure("Card.TFrame", background="#191f2a")
        style.configure("TLabel", background="#10141c", foreground="#e9edf5", font=("Segoe UI", 10))
        style.configure("Muted.TLabel", background="#10141c", foreground="#9ca8ba", font=("Segoe UI", 9))
        style.configure("Card.TLabel", background="#191f2a", foreground="#e9edf5", font=("Segoe UI", 10))
        style.configure("Title.TLabel", background="#10141c", foreground="#f2f5fb", font=("Segoe UI", 23, "bold"))
        style.configure("CardTitle.TLabel", background="#191f2a", foreground="#f2f5fb", font=("Segoe UI", 16, "bold"))
        style.configure("TButton", background="#3b82f6", foreground="#ffffff", padding=(12, 8), font=("Segoe UI", 10, "bold"))
        style.map("TButton", background=[("active", "#2563eb"), ("disabled", "#394456")])
        style.configure("TEntry", fieldbackground="#252d3b", foreground="#f2f5fb", insertcolor="#f2f5fb", padding=8)
        style.configure("Status.TLabel", background="#191f2a", foreground="#b7c1d1", padding=(10, 7))

    def _show_connect_screen(self) -> None:
        self.connect_frame = ttk.Frame(self.root, padding=28)
        self.connect_frame.place(relx=0.5, rely=0.48, anchor="center")
        ttk.Label(self.connect_frame, text="Rabit", style="Title.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(
            self.connect_frame,
            text="Private chats over your local network. No account or internet required.",
            style="Muted.TLabel",
        ).grid(row=1, column=0, sticky="w", pady=(5, 22))

        card = ttk.Frame(self.connect_frame, style="Card.TFrame", padding=22)
        card.grid(row=2, column=0, sticky="ew")
        self.name_var = tk.StringVar(value=socket.gethostname()[:32])
        self.room_var = tk.StringVar(value="Rabit Room")
        self.passphrase_var = tk.StringVar()
        self._form_field(card, 0, "Display name", self.name_var)
        self._form_field(card, 1, "Room name", self.room_var)
        self._form_field(card, 2, "Shared room passphrase", self.passphrase_var, show="*")
        ttk.Label(
            card,
            text="Use the same room name and a long passphrase on each computer (12+ characters).",
            style="Card.TLabel",
            wraplength=410,
        ).grid(row=6, column=0, sticky="w", pady=(9, 15))
        ttk.Button(card, text="Join room", command=self._connect).grid(row=7, column=0, sticky="ew")
        ttk.Label(
            self.connect_frame,
            text="Messages and files are encrypted with the room passphrase. Device names are visible on the LAN.",
            style="Muted.TLabel",
            wraplength=455,
        ).grid(row=3, column=0, sticky="w", pady=(15, 0))

    @staticmethod
    def _form_field(parent: ttk.Frame, row: int, title: str, variable: tk.StringVar, show: str | None = None) -> None:
        ttk.Label(parent, text=title, style="Card.TLabel").grid(row=row * 2, column=0, sticky="w")
        entry = ttk.Entry(parent, textvariable=variable, show=show)
        entry.grid(row=row * 2 + 1, column=0, sticky="ew", pady=(5, 13))
        parent.columnconfigure(0, weight=1)

    def _connect(self) -> None:
        name = self.name_var.get().strip()[:32]
        room = self.room_var.get().strip()[:48]
        passphrase = self.passphrase_var.get()
        if not name or not room:
            messagebox.showerror("Rabit", "Enter a display name and room name.", parent=self.root)
            return
        try:
            key = derive_room_key(passphrase, room)
            client = NetworkClient(load_peer_id(), name, room, key)
            client.start()
        except (OSError, RuntimeError, ValueError) as error:
            messagebox.showerror("Unable to join room", str(error), parent=self.root)
            return

        self.network = client
        self.passphrase_var.set("")
        self.connect_frame.destroy()
        self._build_chat_screen(name, room)
        self._poll_events()

    def _build_chat_screen(self, name: str, room: str) -> None:
        header = ttk.Frame(self.root, padding=(18, 12))
        header.pack(fill="x")
        ttk.Label(header, text="Rabit", style="CardTitle.TLabel").pack(side="left")
        ttk.Label(header, text=f"  {room}", style="Muted.TLabel").pack(side="left", padx=(8, 0))
        ttk.Label(header, text=name, style="Muted.TLabel").pack(side="right")

        body = ttk.Frame(self.root)
        body.pack(fill="both", expand=True, padx=14, pady=(0, 12))
        sidebar = ttk.Frame(body, style="Card.TFrame", padding=10)
        sidebar.pack(side="left", fill="y")
        ttk.Label(sidebar, text="CONVERSATIONS", style="Card.TLabel").pack(anchor="w", padx=8, pady=(7, 10))
        self.contact_list = tk.Listbox(
            sidebar,
            width=25,
            bg="#191f2a",
            fg="#e9edf5",
            selectbackground="#315b9c",
            selectforeground="#ffffff",
            highlightthickness=0,
            borderwidth=0,
            activestyle="none",
            font=("Segoe UI", 10),
        )
        self.contact_list.pack(fill="both", expand=True)
        self.contact_list.bind("<<ListboxSelect>>", self._select_conversation)
        self._refresh_contacts()

        panel = ttk.Frame(body, style="Card.TFrame", padding=12)
        panel.pack(side="left", fill="both", expand=True, padx=(12, 0))
        self.conversation_title = ttk.Label(panel, text="Everyone", style="CardTitle.TLabel")
        self.conversation_title.pack(anchor="w", padx=5, pady=(3, 10))
        log_frame = ttk.Frame(panel, style="Card.TFrame")
        log_frame.pack(fill="both", expand=True)
        scrollbar = ttk.Scrollbar(log_frame)
        scrollbar.pack(side="right", fill="y")
        self.message_log = tk.Text(
            log_frame,
            wrap="word",
            state="disabled",
            bg="#141923",
            fg="#e9edf5",
            insertbackground="#ffffff",
            selectbackground="#315b9c",
            relief="flat",
            padx=14,
            pady=12,
            font=("Segoe UI", 10),
            yscrollcommand=scrollbar.set,
        )
        self.message_log.pack(side="left", fill="both", expand=True)
        scrollbar.configure(command=self.message_log.yview)

        compose = ttk.Frame(panel, style="Card.TFrame", padding=(0, 11, 0, 0))
        compose.pack(fill="x")
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(compose, textvariable=self.message_var)
        self.message_entry.pack(side="left", fill="x", expand=True)
        self.message_entry.bind("<Return>", self._send_message)
        ttk.Button(compose, text="Attach", command=self._choose_file).pack(side="left", padx=(8, 6))
        ttk.Button(compose, text="Send", command=self._send_message).pack(side="left")

        status = ttk.Label(self.root, textvariable=self.status_var, style="Status.TLabel", anchor="w")
        status.pack(fill="x", side="bottom")
        self.message_entry.focus_set()

    def _refresh_contacts(self) -> None:
        selected = self.current_conversation
        self.contact_list.delete(0, tk.END)
        self.contact_ids = ["group"]
        self.contact_list.insert(tk.END, "Everyone  ·  Room")
        for peer_id, peer in sorted(self.peers.items(), key=lambda item: item[1]["name"].casefold()):
            suffix = "" if peer["online"] else "  (offline)"
            self.contact_ids.append(peer_id)
            self.contact_list.insert(tk.END, f"{peer['name']}{suffix}")
        if selected not in self.contact_ids:
            selected = "group"
        self.current_conversation = selected
        index = self.contact_ids.index(selected)
        self.contact_list.selection_set(index)
        self.contact_list.activate(index)
        self._render_conversation()

    def _select_conversation(self, _event: tk.Event) -> None:
        selection = self.contact_list.curselection()
        if not selection:
            return
        self.current_conversation = self.contact_ids[selection[0]]
        if self.current_conversation == "group":
            self.conversation_title.configure(text="Everyone")
        else:
            peer = self.peers.get(self.current_conversation)
            self.conversation_title.configure(text=peer["name"] if peer else "Direct message")
        self._render_conversation()

    def _render_conversation(self) -> None:
        if not hasattr(self, "message_log"):
            return
        self.message_log.configure(state="normal")
        self.message_log.delete("1.0", tk.END)
        for timestamp, sender, text in self.history.get(self.current_conversation, []):
            self.message_log.insert(tk.END, f"{timestamp}  {sender}\n{text}\n\n")
        self.message_log.configure(state="disabled")
        self.message_log.see(tk.END)

    def _append_message(self, conversation: str, sender: str, text: str) -> None:
        timestamp = datetime.now().strftime("%H:%M")
        self.history.setdefault(conversation, []).append((timestamp, sender, text))
        if conversation == self.current_conversation:
            self.message_log.configure(state="normal")
            self.message_log.insert(tk.END, f"{timestamp}  {sender}\n{text}\n\n")
            self.message_log.configure(state="disabled")
            self.message_log.see(tk.END)

    def _send_message(self, _event: tk.Event | None = None) -> str:
        text = self.message_var.get().strip()
        if not text:
            return "break"
        if len(text) > 2000:
            self.status_var.set("Messages are limited to 2000 characters.")
            return "break"
        assert self.network is not None
        scope = "group" if self.current_conversation == "group" else "direct"
        target = None if scope == "group" else self.current_conversation
        try:
            delivered = self.network.send_chat(scope, target, text)
        except (OSError, RuntimeError, ValueError) as error:
            self.status_var.set(str(error))
            return "break"
        if not delivered:
            self.status_var.set("No one is connected to this conversation yet.")
            return "break"
        self.message_var.set("")
        self._append_message(self.current_conversation, "You", text)
        self.status_var.set(f"Sent to {delivered} device{'s' if delivered != 1 else ''}.")
        return "break"

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename(parent=self.root)
        if not path:
            return
        assert self.network is not None
        scope = "group" if self.current_conversation == "group" else "direct"
        target = None if scope == "group" else self.current_conversation
        try:
            self.network.send_file(path, scope, target)
        except (OSError, RuntimeError, ValueError) as error:
            self.status_var.set(str(error))
            return
        self.status_var.set("File transfer started; transfers are limited to 100 MB.")

    def _poll_events(self) -> None:
        if self.network is None:
            return
        while True:
            try:
                event = self.network.events.get_nowait()
            except queue.Empty:
                break
            kind = event.get("type")
            if kind == "peer_connected":
                self.peers[event["peer_id"]] = {"name": event["name"], "online": True}
                self._refresh_contacts()
                self.status_var.set(f"{event['name']} joined the room.")
            elif kind == "peer_disconnected":
                peer = self.peers.get(event["peer_id"])
                if peer:
                    peer["online"] = False
                self._refresh_contacts()
                self.status_var.set(f"{event['name']} disconnected.")
            elif kind == "message":
                conversation = "group" if event["scope"] == "group" else event["peer_id"]
                self.peers.setdefault(event["peer_id"], {"name": event["name"], "online": True})
                self._append_message(conversation, event["name"], event["text"])
            elif kind == "file_received":
                conversation = "group" if event["scope"] == "group" else event["peer_id"]
                self._append_message(
                    conversation,
                    event["name"],
                    f"File received: {event['name']}\nSaved to: {event['path']}",
                )
                self.status_var.set(f"Received {event['name']}.")
            elif kind == "file_sent":
                conversation = "group" if event["scope"] == "group" else event["target"]
                self._append_message(conversation, "You", f"File sent: {event['name']}")
                self.status_var.set(f"Sent {event['name']}.")
            elif kind == "error":
                self.status_var.set(event["text"])
        self.root.after(100, self._poll_events)

    def _close(self) -> None:
        if self.network is not None:
            self.network.stop()
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    RabitApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
