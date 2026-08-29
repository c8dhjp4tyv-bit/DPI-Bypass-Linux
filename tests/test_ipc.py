"""Yerel daemon IPC protokolü için sınır ve biçim regresyon testleri."""

from __future__ import annotations

import asyncio
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src"))

from dpibypass import ipc  # noqa: E402


class TestIpcServerProtocol(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.path = os.path.join(self.tempdir.name, "daemon.sock")
        self.server = None

    async def asyncTearDown(self) -> None:
        if self.server is not None:
            await self.server.stop()
        self.tempdir.cleanup()

    async def _start(self, handler):
        self.server = ipc.IpcServer(handler, path=self.path, group="unused")
        # Bu testler root/grup izinlerini değil protokolü sınar; soket sahipliği
        # için gerçek chown çağırmadan yerel Unix soketiyle uçtan uca çalışır.
        self.server._set_permissions = mock.Mock()
        await self.server.start()
        return self.server

    async def _exchange(self, payload: bytes) -> dict:
        reader, writer = await asyncio.open_unix_connection(self.path)
        try:
            writer.write(payload)
            await writer.drain()
            line = await asyncio.wait_for(reader.readline(), 2)
            self.assertTrue(line, "sunucu yanıt vermeden bağlantıyı kapattı")
            return json.loads(line.decode("utf-8"))
        finally:
            writer.close()
            if hasattr(writer, "wait_closed"):
                await writer.wait_closed()

    async def test_valid_request_round_trip(self):
        async def handler(request):
            return {"ok": True, "data": request["value"]}

        await self._start(handler)
        response = await self._exchange(b'{"cmd":"echo","value":42}\n')
        self.assertEqual(response, {"ok": True, "data": 42})

    async def test_oversized_request_is_rejected_before_handler(self):
        handler = mock.AsyncMock(return_value={"ok": True})
        with mock.patch.object(ipc, "IPC_MAX_MESSAGE_BYTES", 128):
            await self._start(handler)
            response = await self._exchange(b"{" + b"x" * 512 + b"}\n")

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "request-too-large")
        handler.assert_not_awaited()

    async def test_non_mapping_handler_response_is_normalized(self):
        async def handler(_request):
            return ["not", "a", "mapping"]

        await self._start(handler)
        response = await self._exchange(b'{"cmd":"status"}\n')
        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "invalid-response")

    async def test_oversized_handler_response_is_not_written(self):
        async def handler(_request):
            return {"ok": True, "data": "x" * 1024}

        with mock.patch.object(ipc, "IPC_MAX_MESSAGE_BYTES", 256):
            await self._start(handler)
            response = await self._exchange(b'{"cmd":"status"}\n')

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "response-too-large")


class TestIpcClientProtocol(unittest.TestCase):
    def test_non_serializable_request_fails_before_socket_creation(self):
        with mock.patch.object(ipc.socket, "socket") as socket_ctor:
            response = ipc.IpcClient("/unused").call("test", value=object())

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "invalid-request")
        socket_ctor.assert_not_called()

    def test_oversized_request_fails_before_socket_creation(self):
        with mock.patch.object(ipc, "IPC_MAX_MESSAGE_BYTES", 64), \
                mock.patch.object(ipc.socket, "socket") as socket_ctor:
            response = ipc.IpcClient("/unused").call("test", value="x" * 128)

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "request-too-large")
        socket_ctor.assert_not_called()

    def test_response_without_newline_is_bounded(self):
        fake_socket = mock.Mock()
        fake_socket.recv.side_effect = [b"x" * 64, b"x"]
        with mock.patch.object(ipc, "IPC_MAX_MESSAGE_BYTES", 64), \
                mock.patch.object(ipc.socket, "socket", return_value=fake_socket):
            response = ipc.IpcClient("/unused").call("status")

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "response-too-large")
        fake_socket.close.assert_called_once()

    def test_non_mapping_response_is_rejected(self):
        fake_socket = mock.Mock()
        fake_socket.recv.return_value = b"[]\n"
        with mock.patch.object(ipc.socket, "socket", return_value=fake_socket):
            response = ipc.IpcClient("/unused").call("status")

        self.assertFalse(response["ok"])
        self.assertEqual(response["code"], "invalid-response")


if __name__ == "__main__":
    unittest.main(verbosity=2)
