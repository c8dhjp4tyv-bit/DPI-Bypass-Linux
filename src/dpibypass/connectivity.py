"""Masaüstü internet bağlantısı denetimlerini DPI işlemlerinden korur.

NetworkManager belirli aralıklarla küçük bir HTTP adresini yoklar.  Bu adres
otomatik engelli-site keşfine girerse sonraki yoklamalar desync stratejisiyle
değiştirilebilir ve KDE gerçek internet erişimi varken "sınırlı bağlantı"
gösterir.  Etkin URI'yi NetworkManager'ın birleştirilmiş yapılandırmasından
okuyup o alan adını her zaman doğrudan bırakırız.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import urlsplit

from .util import run, which

log = logging.getLogger("dpibypass.connectivity")

# ``NetworkManager --print-config`` bulunamazsa kullanılan yaygın, yalnızca
# bağlantı denetimine ayrılmış uçlar. Etkin URI bulunduğunda da korumak eski
# bir yanlış-öğrenme kaydının dağıtım değişikliğinden sonra geri dönmesini önler.
KNOWN_CHECK_DOMAINS = {
    "ping.archlinux.org",
    "networkcheck.kde.org",
    "nmcheck.gnome.org",
    "connectivity-check.ubuntu.com",
    "connectivitycheck.gstatic.com",
    "conncheck.opensuse.org",
}

_URI_RE = re.compile(r"^\s*uri\s*=\s*(\S.*?)\s*$", re.MULTILINE | re.IGNORECASE)


def _hostname(uri: str) -> str:
    """Geçerli bir HTTP(S) URI'sinden normalleştirilmiş alan adını al."""
    try:
        parsed = urlsplit(uri.strip())
    except ValueError:
        return ""
    if parsed.scheme.lower() not in {"http", "https"}:
        return ""
    return (parsed.hostname or "").lower().strip(".")


def networkmanager_check_domains() -> set[str]:
    """NetworkManager bağlantı denetimi alan adlarını döndür."""
    domains = set(KNOWN_CHECK_DOMAINS)
    executable = which("NetworkManager")
    if not executable:
        return domains

    result = run([executable, "--print-config"], timeout=10)
    if result.returncode != 0:
        log.debug("NetworkManager yapılandırması okunamadı: %s",
                  result.stderr.strip())
        return domains

    for match in _URI_RE.finditer(result.stdout):
        host = _hostname(match.group(1))
        if host:
            domains.add(host)
    return domains
