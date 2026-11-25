# Rabit

Rabit is a small peer-to-peer desktop chat for computers on the same local
network. It discovers Rabit peers over IPv4 multicast; there is no central
server, account, or internet service.

## Run on Windows

Install the Python dependencies once:

```powershell
python -m pip install -r .\requirements.txt
```

Start the app on each computer:

```powershell
 .\rabit1.py
```

Use the same room name and passphrase on each computer. The passphrase must be
at least 12 characters; a longer, unique phrase is recommended. If Windows
Firewall asks, allow Rabit on **Private networks**. The computers must be able
to communicate on the same local network; guest Wi-Fi or client isolation may
block discovery or chat.

Select **Everyone** for room messages or a contact for a direct message. Use
**Attach** to transfer a file (up to 100 MB). Received files are saved in
`%APPDATA%\Rabit\received_files`.

## Encryption and privacy

Chat and file data use AES-GCM authenticated encryption with a key derived
from the shared room passphrase using Scrypt. A recipient verifies transferred
files with SHA-256 before saving them. The passphrase is not saved by Rabit.
Peer names, room identifiers, and device IDs are visible to other devices on
the local network during discovery.

All participants who know the room passphrase can decrypt room traffic,
including direct messages. Direct messages are sent only to their selected
peer by the app, but they are not cryptographically private from other room
members. This initial version is intended for trusted local networks, not
highly sensitive communication.

## Current limits

- IPv4 multicast discovery only; both devices need a network that permits
  multicast and peer-to-peer connections.
- Messages and contact history are kept in memory and are not saved between
  app launches.
- No offline message queue, typing indicators, or voice notes.
- File transfers are limited to 100 MB and are not resumable.

