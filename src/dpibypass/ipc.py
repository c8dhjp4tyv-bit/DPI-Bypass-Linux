"""Arka plan servisi ile GUI arasındaki yerel soket protokolü.

Satır başına bir JSON nesnesi. İstek ``{"cmd": ..., ...}``, yanıt
``{"ok": bool, "data"|"error": ...}``.
"""

from __future__ import annotations

import asyncio
import grp
import json
import logging
import os
import socket
import stat as stat_module
from typing import Any, Awaitable, Callable

from .constants import (RUN_DIR, SOCKET_GROUP, SOCKET_MODE,
                        SOCKET_MODE_DEGRADED, SOCKET_PATH)

log = logging.getLogger("dpibypass.ipc")

Handler = Callable[[dict], Awaitable[dict]]


class IpcServer:
    def __init__(self, handler: Handler, path: str = SOCKET_PATH,
                 group: str = SOCKET_GROUP) -> None:
        self.handler = handler
        self.path = path
        self.group = group
        #: Soket beklenen grup/kip ile kurulabildi mi? Kurulamadıysa soket
        #: yalnızca root'a açıktır ve GUI/CLI bunu bir servis sorunu olarak
        #: bildirir — sessizce herkese açılmaz.
        self.degraded = False
        self.degraded_reason = ""
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        os.makedirs(RUN_DIR, mode=0o755, exist_ok=True)
        try:
            os.unlink(self.path)
        except FileNotFoundError:
            pass
        # Soket, izinleri ayarlanana kadar bile geniş açılmasın: asyncio
        # soketi umask'e göre oluşturur, bu yüzden önce dar bir umask kur.
        previous_umask = os.umask(0o177)
        try:
            self._server = await asyncio.start_unix_server(
                self._client, path=self.path)
        finally:
            os.umask(previous_umask)
        self._set_permissions()
        log.info("Denetim soketi: %s", self.path)

    def _set_permissions(self) -> None:
        """Soketi ``root:dpi-bypass`` / ``0660`` yap ve sonucu **doğrula**.

        Bu soket root servisini yöneten bir denetim kanalıdır; grup
        çözülemezse ya da izinler istendiği gibi uygulanamazsa soket herkese
        açılmaz — yalnızca root'a bırakılır (``0600``) ve durum ``degraded``
        olarak işaretlenir.
        """
        self.degraded = False
        self.degraded_reason = ""
        try:
            gid = int(grp.getgrnam(self.group).gr_gid)
        except (KeyError, TypeError, ValueError):
            self._degrade(f"'{self.group}' grubu sistemde tanımlı değil")
            return
        try:
            os.chown(self.path, 0, gid)
            os.chmod(self.path, SOCKET_MODE)
        except OSError as exc:
            self._degrade(f"soket izinleri ayarlanamadı: {exc}")
            return
        # Uygulandığını varsayma; gerçekten okunup doğrulanır.
        try:
            info = os.stat(self.path)
        except OSError as exc:
            self._degrade(f"soket durumu okunamadı: {exc}")
            return
        mode = stat_module.S_IMODE(info.st_mode)
        if info.st_gid != gid or info.st_uid != 0 or mode != SOCKET_MODE:
            self._degrade(
                f"soket beklenen sahiplikte değil (uid={info.st_uid}, "
                f"gid={info.st_gid}, kip=0{mode:o})")
            return
        log.info("Soket izinleri: root:%s 0%o", self.group, SOCKET_MODE)

    def _degrade(self, reason: str) -> None:
        """Güvenli tarafa düş: soketi yalnız root'a bırak ve gürültülü logla."""
        self.degraded = True
        self.degraded_reason = reason
        try:
            os.chmod(self.path, SOCKET_MODE_DEGRADED)
        except OSError as exc:
            reason = f"{reason}; ayrıca 0{SOCKET_MODE_DEGRADED:o} da uygulanamadı: {exc}"
            self.degraded_reason = reason
        log.error(
            "Denetim soketi güvenli kipe düşürüldü (0%o, yalnız root): %s. "
            "GUI ve komut satırı bağlanamayacak; kurulumu onarın "
            "(sudo groupadd --system %s && sudo systemctl restart dpi-bypass).",
            SOCKET_MODE_DEGRADED, reason, self.group)

    def status(self) -> dict:
        """Soketin gerçek durumu — tanı ekranları için."""
        data: dict[str, Any] = {
            "path": self.path,
            "group": self.group,
            "degraded": self.degraded,
            "reason": self.degraded_reason,
            "expected_mode": f"0{SOCKET_MODE:o}",
        }
        try:
            info = os.stat(self.path)
        except OSError:
            data.update({"exists": False, "uid": None, "gid": None, "mode": None})
            return data
        data.update({
            "exists": True,
            "uid": info.st_uid,
            "gid": info.st_gid,
            "mode": f"0{stat_module.S_IMODE(info.st_mode):o}",
        })
        return data

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await self._server.wait_closed()
            except Exception:
                pass
            self._server = None
        try:
            os.unlink(self.path)
        except OSError:
            pass

    async def _client(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                try:
                    request = json.loads(line.decode("utf-8"))
                    if not isinstance(request, dict):
                        raise ValueError("nesne bekleniyordu")
                except (ValueError, UnicodeDecodeError) as exc:
                    response = {"ok": False, "error": f"geçersiz istek: {exc}"}
                else:
                    try:
                        response = await self.handler(request)
                    except Exception as exc:  # işleyici hatası bağlantıyı düşürmesin
                        log.exception("IPC işleyici hatası")
                        response = {"ok": False, "error": str(exc)}
                writer.write(json.dumps(response, ensure_ascii=False).encode() + b"\n")
                await writer.drain()
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass


class IpcClient:
    """Eşzamanlı istemci (GUI ve komut satırı için)."""

    def __init__(self, path: str = SOCKET_PATH, timeout: float = 30.0) -> None:
        self.path = path
        self.timeout = timeout

    def call(self, cmd: str, **kwargs: Any) -> dict:
        request = {"cmd": cmd}
        request.update(kwargs)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self.path)
            sock.sendall(json.dumps(request, ensure_ascii=False).encode() + b"\n")
            buf = b""
            while b"\n" not in buf:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                buf += chunk
            if not buf:
                return {"ok": False, "error": "servisten yanıt yok"}
            return json.loads(buf.split(b"\n", 1)[0].decode("utf-8"))
        except FileNotFoundError:
            return {"ok": False, "error": "servis çalışmıyor (soket yok)",
                    "code": "no-service"}
        except PermissionError:
            # Sebebi burada tahmin etme: grup üyeliği, oturum grup listesi ve
            # soket izinleri farklı sorunlardır. Tanıyı session_access yapar.
            return {"ok": False,
                    "error": "denetim soketine erişim reddedildi",
                    "code": "permission"}
        except (ConnectionRefusedError, OSError) as exc:
            return {"ok": False, "error": f"servise bağlanılamadı: {exc}",
                    "code": "no-service"}
        except json.JSONDecodeError as exc:
            return {"ok": False, "error": f"bozuk yanıt: {exc}"}
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def available(self) -> bool:
        return os.path.exists(self.path)
