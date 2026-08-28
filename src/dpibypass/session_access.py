"""Denetim soketine erişimin neden çalışmadığını kesin olarak saptar.

Kullanıcı ``sudo usermod -aG dpi-bypass $USER`` komutunu çalıştırdıktan sonra
bile arayüzün "gruba eklenmediniz" demesinin nedeni tek bir şey değildir. En
az beş farklı durum aynı ``PermissionError`` ile sonuçlanır:

* grup hiç yok (kurulum yarım kalmış),
* kullanıcı grup veritabanında gerçekten üye değil,
* kullanıcı üye ama **açık oturumdaki süreç** eski grup listesiyle çalışıyor
  (``usermod`` çalışan süreçlerin ek gruplarını değiştirmez),
* servis çalışmıyor, soket yok,
* soket var ama sahibi/grubu/izni beklenenden farklı.

Bu modül durumu ayırt eder, GUI ile komut satırının aynı tanıyı kullanmasını
sağlar ve yalnızca üçüncü durumda — yani düzeltilebilir olduğunda — süreci
``sg`` ile bir kez yeniden başlatır. Hiçbir yolda kabuk dizgisi elle
kurulmaz; ``shlex.join`` kullanılır.

Modülün tamamı bağımlılıkları parametre olarak alır; böylece root olmadan ve
gerçek bir soket olmadan sınanabilir.
"""

from __future__ import annotations

import grp
import os
import pwd
import shlex
import shutil
import stat as stat_module
import sys
from dataclasses import dataclass, field
from typing import Callable, Sequence

from .constants import (ACCESS_HELPER_FALLBACKS, SOCKET_GROUP, SOCKET_MODE,
                        SOCKET_PATH)

#: ``sg`` ile yeniden başlatma yalnızca bir kez denenir; sonsuz döngü olmaz.
REEXEC_ENV = "DPI_BYPASS_SG"

STATE_OK = "ok"
STATE_ROOT = "root"
STATE_GROUP_MISSING = "group-missing"
STATE_NOT_MEMBER = "not-a-member"
STATE_STALE_SESSION = "stale-session"
STATE_NO_SOCKET = "no-socket"
STATE_SOCKET_PERMISSIONS = "socket-permissions"
STATE_DENIED = "denied"

#: Kullanıcıya gösterilecek kısa başlıklar (GUI ve CLI ortak kullanır).
TITLES = {
    STATE_OK: "Erişim tamam",
    STATE_ROOT: "Erişim tamam (root)",
    STATE_GROUP_MISSING: f"'{SOCKET_GROUP}' grubu sistemde yok",
    STATE_NOT_MEMBER: f"Kullanıcınız '{SOCKET_GROUP}' grubunda değil",
    STATE_STALE_SESSION: "Grup üyeliği bu oturuma henüz yansımadı",
    STATE_NO_SOCKET: "Arka plan servisi çalışmıyor",
    STATE_SOCKET_PERMISSIONS: "Denetim soketinin izinleri beklenenden farklı",
    STATE_DENIED: "Denetim soketine erişim reddedildi",
}


@dataclass
class SocketFacts:
    """Soketin dosya sistemindeki gerçek durumu."""

    path: str = SOCKET_PATH
    exists: bool = False
    is_socket: bool = False
    uid: int | None = None
    gid: int | None = None
    mode: int | None = None
    group_name: str = ""
    accessible: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "exists": self.exists,
            "is_socket": self.is_socket,
            "uid": self.uid,
            "gid": self.gid,
            "mode": None if self.mode is None else f"0{self.mode:o}",
            "group_name": self.group_name,
            "accessible": self.accessible,
            "error": self.error,
        }


@dataclass
class AccessReport:
    """Tek bir tanı: durum, insan tarafından okunur açıklama ve çözüm."""

    state: str = STATE_OK
    detail: str = ""
    remedy: str = ""
    user: str = ""
    uid: int = 0
    group: str = SOCKET_GROUP
    group_gid: int | None = None
    member_in_db: bool = False
    member_in_process: bool = False
    sg_path: str | None = None
    reexec_attempted: bool = False
    socket: SocketFacts = field(default_factory=SocketFacts)

    @property
    def ok(self) -> bool:
        return self.state in (STATE_OK, STATE_ROOT)

    @property
    def title(self) -> str:
        return TITLES.get(self.state, "Erişim sorunu")

    @property
    def can_reexec(self) -> bool:
        """Süreç ``sg`` ile yeniden başlatılarak düzeltilebilir mi?"""
        return self.state == STATE_STALE_SESSION and bool(self.sg_path)

    @property
    def needs_admin(self) -> bool:
        """Düzeltme yönetici yetkisi gerektiriyor mu?"""
        return self.state in (STATE_GROUP_MISSING, STATE_NOT_MEMBER)

    def to_dict(self) -> dict:
        return {
            "state": self.state,
            "title": self.title,
            "detail": self.detail,
            "remedy": self.remedy,
            "user": self.user,
            "uid": self.uid,
            "group": self.group,
            "group_gid": self.group_gid,
            "member_in_db": self.member_in_db,
            "member_in_process": self.member_in_process,
            "can_reexec": self.can_reexec,
            "needs_admin": self.needs_admin,
            "socket": self.socket.to_dict(),
        }


# --------------------------------------------------------------------------- #
# tek tek olgular
# --------------------------------------------------------------------------- #
def group_gid(group: str = SOCKET_GROUP,
              getgrnam: Callable[[str], object] = grp.getgrnam) -> int | None:
    """Grubun GID'i; grup NSS'te yoksa ``None``."""
    try:
        return int(getgrnam(group).gr_gid)      # type: ignore[attr-defined]
    except (KeyError, AttributeError, TypeError, ValueError):
        return None


def current_user(uid: int | None = None,
                 getpwuid: Callable[[int], object] = pwd.getpwuid) -> str:
    """Etkin kullanıcının adı; çözülemezse boş dizge."""
    if uid is None:
        uid = os.getuid()
    try:
        return str(getpwuid(uid).pw_name)       # type: ignore[attr-defined]
    except (KeyError, AttributeError, TypeError):
        return os.environ.get("USER", "") or os.environ.get("LOGNAME", "")


def db_membership(user: str, gid: int | None, group: str = SOCKET_GROUP,
                  getpwnam: Callable[[str], object] = pwd.getpwnam,
                  getgrouplist: Callable[[str, int], Sequence[int]] = os.getgrouplist,
                  getgrnam: Callable[[str], object] = grp.getgrnam) -> bool:
    """Kullanıcı **grup veritabanına göre** üye mi?

    ``/etc/group`` tek kaynak değildir: LDAP/SSSD gibi NSS sağlayıcıları ve
    kullanıcının birincil grubu da üyelik sayılır. Bu yüzden önce
    ``os.getgrouplist`` (NSS'i sorgular), sonra düz ``gr_mem`` denenir.
    """
    if not user:
        return False
    if gid is not None:
        try:
            entry = getpwnam(user)
            if gid in [int(item) for item in
                       getgrouplist(user, int(entry.pw_gid))]:  # type: ignore[attr-defined]
                return True
        except (KeyError, AttributeError, OSError, TypeError, ValueError):
            pass
    try:
        members = getgrnam(group).gr_mem or []  # type: ignore[attr-defined]
    except (KeyError, AttributeError, TypeError):
        return False
    return user in members


def process_membership(gid: int | None,
                       getgroups: Callable[[], Sequence[int]] = os.getgroups,
                       getegid: Callable[[], int] = os.getegid) -> bool:
    """Çalışan sürecin ek grupları arasında bu GID var mı?"""
    if gid is None:
        return False
    try:
        if gid in list(getgroups()):
            return True
    except OSError:
        pass
    try:
        return int(getegid()) == gid
    except OSError:
        return False


def socket_facts(path: str = SOCKET_PATH,
                 stat_fn: Callable[[str], object] = os.stat,
                 access_fn: Callable[[str, int], bool] = os.access,
                 getgrgid: Callable[[int], object] = grp.getgrgid) -> SocketFacts:
    """Soketin sahibi, grubu, kipi ve gerçekten erişilebilir olup olmadığı."""
    facts = SocketFacts(path=path)
    try:
        info = stat_fn(path)
    except FileNotFoundError:
        return facts
    except OSError as exc:
        facts.error = str(exc)
        return facts
    facts.exists = True
    facts.uid = int(info.st_uid)                # type: ignore[attr-defined]
    facts.gid = int(info.st_gid)                # type: ignore[attr-defined]
    facts.mode = stat_module.S_IMODE(int(info.st_mode))  # type: ignore[attr-defined]
    facts.is_socket = stat_module.S_ISSOCK(int(info.st_mode))  # type: ignore[attr-defined]
    try:
        facts.group_name = str(getgrgid(facts.gid).gr_name)   # type: ignore[attr-defined]
    except (KeyError, AttributeError, TypeError, OverflowError):
        facts.group_name = ""
    try:
        facts.accessible = bool(access_fn(path, os.R_OK | os.W_OK))
    except OSError:
        facts.accessible = False
    return facts


def sg_path(which_fn: Callable[[str], str | None] = shutil.which,
            access_fn: Callable[[str, int], bool] = os.access) -> str | None:
    """``sg`` (shadow-utils) yolu; dağıtımlar arasında konumu değişir.

    ``PATH`` daraltılmış olabilir (masaüstü oturumundan başlatılan .desktop
    girdileri), bu yüzden ``which`` sonuçsuz kalırsa bilinen yollar da bakılır.
    """
    found = which_fn("sg")
    if found:
        return found
    for candidate in ("/usr/bin/sg", "/bin/sg", "/usr/local/bin/sg"):
        if access_fn(candidate, os.X_OK):
            return candidate
    return None


def access_helper_path() -> str | None:
    """pkexec ile çalıştırılacak erişim onarım yardımcısının yolu."""
    for path in ACCESS_HELPER_FALLBACKS:
        if os.access(path, os.X_OK):
            return path
    local = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__)))),
        "bin", "dpi-bypass-access-helper")
    return local if os.access(local, os.X_OK) else None


# --------------------------------------------------------------------------- #
# tanı
# --------------------------------------------------------------------------- #
def analyze(group: str = SOCKET_GROUP, path: str = SOCKET_PATH,
            uid: int | None = None, euid: int | None = None,
            getgrnam: Callable[[str], object] = grp.getgrnam,
            getpwuid: Callable[[int], object] = pwd.getpwuid,
            getpwnam: Callable[[str], object] = pwd.getpwnam,
            getgrouplist: Callable[[str, int], Sequence[int]] = os.getgrouplist,
            getgroups: Callable[[], Sequence[int]] = os.getgroups,
            getegid: Callable[[], int] = os.getegid,
            stat_fn: Callable[[str], object] = os.stat,
            access_fn: Callable[[str, int], bool] = os.access,
            getgrgid: Callable[[int], object] = grp.getgrgid,
            which_fn: Callable[[str], str | None] = shutil.which,
            sg_lookup: Callable[..., str | None] | None = None) -> AccessReport:
    """Erişim durumunu tek bir sebebe indirger.

    Sıralama kasıtlıdır: önce kullanıcı/grup katmanı (kullanıcının kendi
    çözebileceği ya da yöneticinin düzelteceği kısım), sonra servis ve soket
    katmanı. Böylece "gruba eklenmediniz" mesajı yalnızca gerçekten grup
    sorunu varken görünür.
    """
    if uid is None:
        uid = os.getuid()
    if euid is None:
        euid = os.geteuid()

    facts = socket_facts(path, stat_fn=stat_fn, access_fn=access_fn,
                         getgrgid=getgrgid)
    user = current_user(uid, getpwuid=getpwuid)
    gid = group_gid(group, getgrnam=getgrnam)
    lookup = sg_lookup or sg_path
    report = AccessReport(user=user, uid=uid, group=group, group_gid=gid,
                          socket=facts, sg_path=lookup(which_fn))

    report.member_in_db = db_membership(user, gid, group, getpwnam=getpwnam,
                                        getgrouplist=getgrouplist,
                                        getgrnam=getgrnam)
    report.member_in_process = process_membership(gid, getgroups=getgroups,
                                                  getegid=getegid)

    if euid == 0:
        # root sokete zaten erişir; yine de kurulumun masaüstü kullanıcısı
        # için bozuk olduğunu gizleme — 'dpi-bypass doctor' bunun içindir.
        if gid is None:
            report.state = STATE_GROUP_MISSING
            report.detail = (
                f"'{group}' grubu sistemde tanımlı değil. root bağlanabilir, "
                "ancak masaüstü kullanıcısı bağlanamaz.")
            report.remedy = f"sudo groupadd --system {group}"
            return report
        if not facts.exists:
            report.state = STATE_NO_SOCKET
            report.detail = f"Denetim soketi yok: {path}"
            report.remedy = "sudo systemctl start dpi-bypass"
            return report
        report.state = STATE_ROOT
        report.detail = "root olarak çalışılıyor; grup üyeliği gerekmiyor."
        return report

    if gid is None:
        report.state = STATE_GROUP_MISSING
        report.detail = (
            f"'{group}' grubu sistemde tanımlı değil. Kurulum betiği grubu "
            "oluşturamamış olabilir.")
        report.remedy = f"sudo groupadd --system {group}"
        return report

    if not report.member_in_db:
        report.state = STATE_NOT_MEMBER
        report.detail = (
            f"'{user or 'kullanıcı'}' hesabı grup veritabanında '{group}' "
            "grubunun üyesi değil.")
        report.remedy = f"sudo usermod -aG {group} {user or '$USER'}"
        return report

    if not report.member_in_process:
        report.state = STATE_STALE_SESSION
        report.detail = (
            f"'{user}' hesabı '{group}' grubunda, ancak bu süreç grup listesini "
            "oturum açıldığında almış. usermod çalışan süreçlerin gruplarını "
            "değiştirmez.")
        report.remedy = (
            f"{report.sg_path or 'sg'} {group} -c ..." if report.sg_path else
            "Oturumu kapatıp yeniden açın (sg komutu bulunamadı).")
        return report

    if not facts.exists:
        report.state = STATE_NO_SOCKET
        report.detail = f"Denetim soketi yok: {path}"
        report.remedy = "sudo systemctl start dpi-bypass"
        return report

    if facts.gid != gid or (facts.mode is not None
                            and (facts.mode & 0o060) != 0o060):
        report.state = STATE_SOCKET_PERMISSIONS
        report.detail = (
            f"Soketin grubu/izni beklenenden farklı: "
            f"gid={facts.gid} (beklenen {gid}), "
            f"kip=0{(facts.mode or 0):o} (beklenen 0{SOCKET_MODE:o}). "
            "Bu bir servis tarafı sorunudur.")
        report.remedy = "sudo systemctl restart dpi-bypass"
        return report

    if not facts.accessible:
        report.state = STATE_DENIED
        report.detail = (
            "Grup üyeliği ve soket izinleri doğru görünüyor, ancak çekirdek "
            "erişimi yine de reddediyor. SELinux/AppArmor ya da bir sandbox "
            "(Flatpak/Snap) araya giriyor olabilir.")
        report.remedy = "journalctl -u dpi-bypass -n 40"
        return report

    report.state = STATE_OK
    report.detail = "Denetim soketine erişilebiliyor."
    return report


# --------------------------------------------------------------------------- #
# sg ile yeniden başlatma
# --------------------------------------------------------------------------- #
def default_argv(argv: Sequence[str] | None = None,
                 executable: str = "") -> list[str]:
    """Süreci yeniden başlatmak için kullanılacak argüman dizisi.

    Betik doğrudan çalıştırılabilir durumdaysa kendi yolu kullanılır; değilse
    (``python3 bin/dpi-bypass`` gibi) yorumlayıcı öne eklenir.
    """
    argv = list(argv if argv is not None else sys.argv)
    script = os.path.realpath(argv[0]) if argv else ""
    rest = [str(item) for item in argv[1:]]
    if script and os.access(script, os.X_OK):
        return [script] + rest
    return [executable or sys.executable, script] + rest


def build_sg_argv(group: str, argv: Sequence[str]) -> list[str]:
    """``sg GRUP -c "..."`` çağrısı — kabuk alıntılaması ``shlex`` ile.

    Elle ``'…'`` sarmalamak, içinde tek tırnak geçen bir yol ya da argümanla
    bozulur ve kabuğa istenmeyen kelime bölmesi sızdırır.
    """
    return ["sg", group, "-c", shlex.join([str(item) for item in argv])]


def maybe_reexec_with_group(
        group: str = SOCKET_GROUP, path: str = SOCKET_PATH,
        argv: Sequence[str] | None = None,
        environ: dict | None = None,
        execvp: Callable[[str, Sequence[str]], None] = os.execvp,
        report: AccessReport | None = None,
        **analyze_kwargs) -> AccessReport:
    """Yalnız "oturum grubu eski" durumunda süreci ``sg`` ile yeniden başlat.

    Başarılı olursa bu fonksiyondan dönülmez (``execvp`` süreci değiştirir).
    Her koşulda tanı raporu döndürülür; çağıran taraf kullanıcıya doğru
    mesajı gösterebilsin diye başarısızlık sebebi ``remedy`` alanına yazılır.
    """
    env = os.environ if environ is None else environ
    if report is None:
        report = analyze(group=group, path=path, **analyze_kwargs)
    if env.get(REEXEC_ENV):
        # Bir kez denendi; ikinci kez denemek sonsuz döngü olurdu.
        if report.state == STATE_STALE_SESSION:
            report.detail += (
                " Uygulama bir kez 'sg' ile yeniden başlatıldı ama grup yine "
                "alınamadı.")
            report.remedy = "Oturumu kapatıp yeniden açın."
        return report
    if report.state != STATE_STALE_SESSION:
        return report
    if not report.sg_path:
        report.remedy = (
            "'sg' komutu bulunamadı (shadow-utils paketi). Oturumu kapatıp "
            "yeniden açın.")
        return report

    command = build_sg_argv(group, default_argv(argv))
    env[REEXEC_ENV] = "1"
    report.reexec_attempted = True
    try:
        execvp(command[0], command)
    except OSError as exc:
        env.pop(REEXEC_ENV, None)
        report.detail += f" 'sg' ile yeniden başlatma başarısız: {exc}"
        report.remedy = "Oturumu kapatıp yeniden açın."
    return report
