import queue
import tempfile
import time
import unittest
import uuid
from pathlib import Path

from rabit_network import NetworkClient, _clean_filename, _open, _seal, derive_room_key


class EncryptionTests(unittest.TestCase):
    def test_encrypted_frame_round_trip(self):
        key = derive_room_key("correct horse battery staple", "Rabit Room")
        payload = {"kind": "chat", "text": "hello over LAN"}

        self.assertEqual(_open(key, _seal(key, payload)), payload)

    def test_wrong_room_passphrase_cannot_decrypt_frame(self):
        sender_key = derive_room_key("correct horse battery staple", "Rabit Room")
        other_key = derive_room_key("another long passphrase", "Rabit Room")

        with self.assertRaisesRegex(ValueError, "authentication failed"):
            _open(other_key, _seal(sender_key, {"kind": "chat", "text": "secret"}))

    def test_room_name_is_part_of_the_key(self):
        first = derive_room_key("correct horse battery staple", "Rabit Room")
        second = derive_room_key("correct horse battery staple", "Other Room")

        self.assertNotEqual(first, second)

    def test_passphrase_must_be_long_enough(self):
        with self.assertRaisesRegex(ValueError, "at least 12"):
            derive_room_key("short", "Rabit Room")

    def test_received_filename_is_safe(self):
        self.assertEqual(_clean_filename(r"..\..\secret.txt"), "secret.txt")
        self.assertEqual(_clean_filename("bad:name?.txt"), "bad_name_.txt")


class NetworkIntegrationTests(unittest.TestCase):
    def test_discovery_chat_and_file_transfer(self):
        room = "Rabit Test " + uuid.uuid4().hex[:8]
        key = derive_room_key("correct horse battery staple", room)
        sender = NetworkClient(str(uuid.uuid4()), "Test Sender", room, key)
        recipient = NetworkClient(str(uuid.uuid4()), "Test Recipient", room, key)
        source_path = None
        received_path = None
        try:
            sender.start()
            recipient.start()
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if sender.connected_peers() and recipient.connected_peers():
                    break
                time.sleep(0.1)
            self.assertTrue(sender.connected_peers(), "sender did not discover the recipient")
            self.assertTrue(recipient.connected_peers(), "recipient did not connect to the sender")

            self.assertEqual(sender.send_chat("group", None, "integration hello"), 1)
            message = self._wait_for_event(recipient, "message", timeout=3)
            self.assertEqual(message["text"], "integration hello")

            with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as source:
                source.write(b"Rabit integration file payload")
                source_path = Path(source.name)
            sender.send_file(str(source_path), "group", None)
            received = self._wait_for_event(recipient, "file_received", timeout=8)
            received_path = Path(received["path"])
            self.assertEqual(received_path.read_bytes(), source_path.read_bytes())
        finally:
            sender.stop()
            recipient.stop()
            if source_path is not None:
                source_path.unlink(missing_ok=True)
            if received_path is not None:
                received_path.unlink(missing_ok=True)

    @staticmethod
    def _wait_for_event(client, event_type, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                event = client.events.get(timeout=0.1)
            except queue.Empty:
                continue
            if event.get("type") == event_type:
                return event
        raise AssertionError(f"Timed out waiting for {event_type} event")


if __name__ == "__main__":
    unittest.main()
