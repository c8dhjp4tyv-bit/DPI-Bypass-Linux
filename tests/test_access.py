"""Grup / oturum / soket erişimi testleri — root ve gerçek soket gerekmez.

Buradaki senaryolar kullanıcının bildirdiği hatanın tam kaynağını kapsar:
``sudo usermod -aG dpi-bypass $USER`` çalıştırıldıktan sonra bile arayüzün
"gruba eklenmediniz" demesi. Ayrı ayrı sınanan durumlar: grup yok, üye değil,
üye ama oturum grubu eski, servis yok, soket izni bozuk.
"""

from __future__ import annotations

import grp
import json
import os
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "src"))

from dpibypass import session_access  # noqa: E402
from dpibypass.constants import SOCKET_MODE, SOCKET_MODE_DEGRADED  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INSTALL_SH = os.path.join(REPO_ROOT, "install.sh")

GROUP = "dpi-bypass"
GROUP_GID = 970
USER = "ayse"
USER_UID = 1000
USER_PRIMARY_GID = 1000
SOCKET = "/run/dpi-bypass/daemon.sock"


class FakeStat:
    def __init__(self, uid=0, gid=GROUP_GID, mode=0o660, is_socket=True):
        self.st_uid = uid
        self.st_gid = gid
        self.st_mode = (stat.S_IFSOCK if is_socket else stat.S_IFREG) | mode


class FakeGroup:
    def __init__(self, name, gid, members):
        self.gr_name = name
        self.gr_gid = gid
        self.gr_mem = list(members)


class FakePasswd:
    def __init__(self, name=USER, uid=USER_UID, gid=USER_PRIMARY_GID):
        self.pw_name = name
        self.pw_uid = uid
        self.pw_gid = gid


def world(group_exists=True, members=(USER,), nss_groups=None,
          process_groups=(1000,), socket_stat=None, socket_error=None,
          accessible=True, sg="/usr/bin/sg") -> dict:
    """analyze() için tek yerden kurulmuş sahte sistem."""
    def getgrnam(name):
        if name == GROUP and group_exists:
            return FakeGroup(GROUP, GROUP_GID, members)
        raise KeyError(name)

    def getgrgid(gid):
        if gid == GROUP_GID and group_exists:
            return FakeGroup(GROUP, GROUP_GID, members)
        raise KeyError(gid)

    def stat_fn(path):
        if socket_error is not None:
            raise socket_error
        if socket_stat is None:
            raise FileNotFoundError(path)
        return socket_stat

    return {
        "group": GROUP,
        "path": SOCKET,
        "uid": USER_UID,
        "euid": USER_UID,
        "getgrnam": getgrnam,
        "getgrgid": getgrgid,
        "getpwuid": lambda uid: FakePasswd(),
        "getpwnam": lambda name: FakePasswd(name),
        "getgrouplist": lambda name, gid: list(
            nss_groups if nss_groups is not None
            else ([gid, GROUP_GID] if name in members else [gid])),
        "getgroups": lambda: list(process_groups),
        "getegid": lambda: USER_PRIMARY_GID,
        "stat_fn": stat_fn,
        "access_fn": lambda path, mode: accessible,
        "which_fn": lambda name: sg if name == "sg" else None,
        # Gerçek sistemde /usr/bin/sg olabilir; test onu görmemeli.
        "sg_lookup": lambda which_fn=None, **_kwargs: sg,
    }


class TestAccessDiagnosis(unittest.TestCase):
    def test_everything_correct_is_ok(self):
        report = session_access.analyze(**world(
            process_groups=(1000, GROUP_GID), socket_stat=FakeStat()))
        self.assertEqual(report.state, session_access.STATE_OK)
        self.assertTrue(report.ok)
        self.assertFalse(report.can_reexec)
        self.assertFalse(report.needs_admin)

    def test_missing_group_is_reported_as_missing_group(self):
        report = session_access.analyze(**world(group_exists=False))
        self.assertEqual(report.state, session_access.STATE_GROUP_MISSING)
        self.assertTrue(report.needs_admin)
        self.assertIn("groupadd", report.remedy)

    def test_user_not_in_group_database(self):
        report = session_access.analyze(**world(
            members=(), nss_groups=[USER_PRIMARY_GID],
            socket_stat=FakeStat()))
        self.assertEqual(report.state, session_access.STATE_NOT_MEMBER)
        self.assertFalse(report.member_in_db)
        self.assertIn("usermod -aG", report.remedy)
        self.assertTrue(report.needs_admin)

    def test_member_in_db_but_not_in_process_is_a_stale_session(self):
        """Kullanıcının bildirdiği asıl hata: usermod çalıştı, GUI hâlâ diyor ki…"""
        report = session_access.analyze(**world(
            process_groups=(1000,), socket_stat=FakeStat()))
        self.assertEqual(report.state, session_access.STATE_STALE_SESSION)
        self.assertTrue(report.member_in_db)
        self.assertFalse(report.member_in_process)
        self.assertTrue(report.can_reexec)
        self.assertFalse(report.needs_admin)

    def test_stale_session_without_sg_cannot_reexec(self):
        report = session_access.analyze(**world(
            process_groups=(1000,), socket_stat=FakeStat(), sg=None))
        self.assertEqual(report.state, session_access.STATE_STALE_SESSION)
        self.assertFalse(report.can_reexec)
        self.assertIn("Oturumu kapatıp", report.remedy)

    def test_nss_only_membership_counts(self):
        """LDAP/SSSD üyeliği /etc/group'ta görünmez ama geçerlidir."""
        report = session_access.analyze(**world(
            members=(), nss_groups=[USER_PRIMARY_GID, GROUP_GID],
            process_groups=(1000, GROUP_GID), socket_stat=FakeStat()))
        self.assertEqual(report.state, session_access.STATE_OK)

    def test_primary_group_membership_counts(self):
        report = session_access.analyze(**world(
            members=(), nss_groups=[GROUP_GID],
            process_groups=(GROUP_GID,), socket_stat=FakeStat()))
        self.assertEqual(report.state, session_access.STATE_OK)

    def test_missing_socket_is_a_service_problem(self):
        report = session_access.analyze(**world(
            process_groups=(1000, GROUP_GID), socket_stat=None))
        self.assertEqual(report.state, session_access.STATE_NO_SOCKET)
        self.assertIn("systemctl start", report.remedy)

    def test_socket_with_wrong_group_is_a_socket_problem(self):
        report = session_access.analyze(**world(
            process_groups=(1000, GROUP_GID),
            socket_stat=FakeStat(gid=0), accessible=False))
        self.assertEqual(report.state, session_access.STATE_SOCKET_PERMISSIONS)
        self.assertIn("systemctl restart", report.remedy)

    def test_socket_with_wrong_mode_is_a_socket_problem(self):
        report = session_access.analyze(**world(
            process_groups=(1000, GROUP_GID),
            socket_stat=FakeStat(mode=0o600), accessible=False))
        self.assertEqual(report.state, session_access.STATE_SOCKET_PERMISSIONS)

    def test_permission_denied_with_correct_setup_is_not_a_group_error(self):
        report = session_access.analyze(**world(
            process_groups=(1000, GROUP_GID), socket_stat=FakeStat(),
            accessible=False))
        self.assertEqual(report.state, session_access.STATE_DENIED)
        self.assertNotIn("usermod", report.remedy)

    def test_root_never_needs_the_group(self):
        settings = world(socket_stat=FakeStat())
        settings["euid"] = 0
        settings["uid"] = 0
        report = session_access.analyze(**settings)
        self.assertEqual(report.state, session_access.STATE_ROOT)
        self.assertTrue(report.ok)

    def test_root_without_socket_reports_the_service(self):
        settings = world()
        settings["euid"] = 0
        report = session_access.analyze(**settings)
        self.assertEqual(report.state, session_access.STATE_NO_SOCKET)

    def test_root_still_reports_a_broken_install_for_the_desktop_user(self):
        """root bağlanabiliyor diye kurulumun bozukluğu gizlenmemeli."""
        settings = world(group_exists=False, socket_stat=FakeStat(gid=0))
        settings["euid"] = 0
        report = session_access.analyze(**settings)
        self.assertEqual(report.state, session_access.STATE_GROUP_MISSING)
        self.assertFalse(report.ok)

    def test_report_is_json_serialisable(self):
        report = session_access.analyze(**world(socket_stat=FakeStat()))
        self.assertTrue(json.dumps(report.to_dict()))
        self.assertIn("state", report.to_dict())


class TestSgReexec(unittest.TestCase):
    def test_command_is_quoted_with_shlex_not_by_hand(self):
        argv = ["/usr/bin/dpi-bypass", "set", "extra_domains=it's fine",
                "--json"]
        command = session_access.build_sg_argv(GROUP, argv)
        self.assertEqual(command[:3], ["sg", GROUP, "-c"])
        # sg komutu /bin/sh -c ile çalıştırır: geri ayrıştırma birebir olmalı.
        self.assertEqual(shlex.split(command[3]), argv)

    def test_hand_rolled_quoting_would_have_broken(self):
        """Eski '…' sarmalaması tek tırnak içeren argümanda bozuluyordu."""
        argv = ["/usr/bin/dpi-bypass", "it's"]
        broken = " ".join(f"'{item}'" for item in argv)
        # Eski biçim kabuğa bozuk bir dizge veriyordu (kapanmayan tırnak).
        with self.assertRaises(ValueError):
            shlex.split(broken)
        self.assertEqual(
            shlex.split(session_access.build_sg_argv(GROUP, argv)[3]), argv)

    def test_stale_session_triggers_a_single_reexec(self):
        calls: list[list[str]] = []
        env: dict = {}
        settings = world(process_groups=(1000,), socket_stat=FakeStat())
        report = session_access.maybe_reexec_with_group(
            argv=["/usr/bin/dpi-bypass-gui"], environ=env,
            execvp=lambda binary, argv: calls.append(list(argv)), **settings)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][:3], ["sg", GROUP, "-c"])
        self.assertEqual(env.get(session_access.REEXEC_ENV), "1")
        self.assertTrue(report.reexec_attempted)

    def test_reexec_loop_is_prevented_by_the_guard(self):
        calls: list[list[str]] = []
        env = {session_access.REEXEC_ENV: "1"}
        settings = world(process_groups=(1000,), socket_stat=FakeStat())
        report = session_access.maybe_reexec_with_group(
            argv=["/usr/bin/dpi-bypass-gui"], environ=env,
            execvp=lambda binary, argv: calls.append(list(argv)), **settings)
        self.assertEqual(calls, [])
        self.assertIn("Oturumu kapatıp", report.remedy)

    def test_no_reexec_when_the_user_is_not_a_member(self):
        calls: list[list[str]] = []
        settings = world(members=(), nss_groups=[USER_PRIMARY_GID],
                         socket_stat=FakeStat())
        report = session_access.maybe_reexec_with_group(
            argv=["/usr/bin/dpi-bypass-gui"], environ={},
            execvp=lambda binary, argv: calls.append(list(argv)), **settings)
        self.assertEqual(calls, [])
        self.assertEqual(report.state, session_access.STATE_NOT_MEMBER)

    def test_no_reexec_when_everything_is_already_correct(self):
        calls: list[list[str]] = []
        settings = world(process_groups=(1000, GROUP_GID),
                         socket_stat=FakeStat())
        report = session_access.maybe_reexec_with_group(
            argv=["/usr/bin/dpi-bypass-gui"], environ={},
            execvp=lambda binary, argv: calls.append(list(argv)), **settings)
        self.assertEqual(calls, [])
        self.assertEqual(report.state, session_access.STATE_OK)

    def test_missing_sg_reports_the_reason_instead_of_failing_silently(self):
        settings = world(process_groups=(1000,), socket_stat=FakeStat(),
                         sg=None)
        report = session_access.maybe_reexec_with_group(
            argv=["/usr/bin/dpi-bypass-gui"], environ={},
            execvp=lambda binary, argv: self.fail("sg yokken exec olmamalı"),
            **settings)
        self.assertIn("sg", report.remedy)

    def test_failed_exec_clears_the_guard_and_explains(self):
        env: dict = {}
        settings = world(process_groups=(1000,), socket_stat=FakeStat())

        def boom(binary, argv):
            raise OSError(13, "Permission denied")

        report = session_access.maybe_reexec_with_group(
            argv=["/usr/bin/dpi-bypass-gui"], environ=env, execvp=boom,
            **settings)
        self.assertNotIn(session_access.REEXEC_ENV, env)
        self.assertIn("Oturumu kapatıp", report.remedy)

    def test_non_executable_script_is_relaunched_via_the_interpreter(self):
        with tempfile.TemporaryDirectory() as directory:
            script = os.path.join(directory, "dpi-bypass")
            with open(script, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\n")
            os.chmod(script, 0o644)
            argv = session_access.default_argv([script, "status"])
        self.assertEqual(argv[0], sys.executable)
        self.assertEqual(argv[1:], [script, "status"])

    def test_executable_script_is_relaunched_directly(self):
        with tempfile.TemporaryDirectory() as directory:
            script = os.path.join(directory, "dpi-bypass")
            with open(script, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env python3\n")
            os.chmod(script, 0o755)
            argv = session_access.default_argv([script, "status"])
        self.assertEqual(argv, [os.path.realpath(script), "status"])


class TestSocketFacts(unittest.TestCase):
    def test_real_socket_is_read_correctly(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "daemon.sock")
            import socket as socket_module
            server = socket_module.socket(socket_module.AF_UNIX,
                                          socket_module.SOCK_STREAM)
            self.addCleanup(server.close)
            server.bind(path)
            self.addCleanup(lambda: os.path.exists(path) and os.unlink(path))
            os.chmod(path, 0o660)
            facts = session_access.socket_facts(path)
        self.assertTrue(facts.exists)
        self.assertTrue(facts.is_socket)
        self.assertEqual(facts.mode, 0o660)
        self.assertEqual(facts.uid, os.getuid())

    def test_missing_socket_is_not_an_error(self):
        facts = session_access.socket_facts("/definitely/missing/daemon.sock")
        self.assertFalse(facts.exists)
        self.assertEqual(facts.error, "")

    def test_unreadable_parent_is_reported_as_an_error(self):
        facts = session_access.socket_facts(
            "/proc/1/root/definitely/missing.sock",
            stat_fn=lambda path: (_ for _ in ()).throw(
                PermissionError(13, "Permission denied")))
        self.assertFalse(facts.exists)
        self.assertIn("Permission denied", facts.error)


class TestIpcSocketSecurity(unittest.IsolatedAsyncioTestCase):
    """Root daemon'ın denetim soketi hiçbir koşulda herkese açılmamalı."""

    async def make_server(self, directory: str, group: str):
        from dpibypass.ipc import IpcServer

        async def handler(request):
            return {"ok": True, "data": "pong"}

        server = IpcServer(handler, path=os.path.join(directory, "daemon.sock"),
                           group=group)
        self.addCleanup(lambda: None)
        await server.start()
        self.addCleanup(lambda: None)
        return server

    async def test_missing_group_degrades_to_root_only_not_world_writable(self):
        with tempfile.TemporaryDirectory() as directory:
            server = await self.make_server(directory, "dpi-bypass-yok-boyle-grup")
            try:
                mode = stat.S_IMODE(os.stat(server.path).st_mode)
                self.assertTrue(server.degraded)
                self.assertEqual(mode, SOCKET_MODE_DEGRADED)
                self.assertEqual(mode & 0o007, 0, "soket herkese açık olmamalı")
                self.assertIn("grubu", server.degraded_reason)
            finally:
                await server.stop()

    async def test_socket_is_never_world_accessible_even_before_chmod(self):
        with tempfile.TemporaryDirectory() as directory:
            server = await self.make_server(directory, "dpi-bypass-yok-boyle-grup")
            try:
                self.assertEqual(
                    stat.S_IMODE(os.stat(server.path).st_mode) & 0o077 & ~0o060,
                    0)
            finally:
                await server.stop()

    async def test_status_reports_the_real_socket_state(self):
        with tempfile.TemporaryDirectory() as directory:
            server = await self.make_server(directory, "dpi-bypass-yok-boyle-grup")
            try:
                status = server.status()
                self.assertTrue(status["exists"])
                self.assertTrue(status["degraded"])
                self.assertEqual(status["expected_mode"], f"0{SOCKET_MODE:o}")
            finally:
                await server.stop()

    async def test_existing_group_sets_owner_group_and_mode(self):
        """Sistemde gerçekten var olan bir grupla tam beklenen sonuç alınır."""
        own_gid = os.getgid()
        try:
            own_group = grp.getgrgid(own_gid).gr_name
        except KeyError:
            self.skipTest("kendi grup adı çözülemedi")
        with tempfile.TemporaryDirectory() as directory:
            server = await self.make_server(directory, own_group)
            try:
                info = os.stat(server.path)
                if os.geteuid() == 0:
                    self.assertFalse(server.degraded)
                    self.assertEqual(stat.S_IMODE(info.st_mode), SOCKET_MODE)
                    self.assertEqual(info.st_gid, own_gid)
                else:
                    # root olmadan chown başarısızdır; güvenli tarafa düşülür.
                    self.assertTrue(server.degraded)
                    self.assertEqual(stat.S_IMODE(info.st_mode),
                                     SOCKET_MODE_DEGRADED)
            finally:
                await server.stop()


def run_installer_function(script: str, stubs: dict,
                           env: dict | None = None) -> subprocess.CompletedProcess:
    """install.sh'i yalnız fonksiyon kitaplığı olarak yükleyip parça çalıştırır.

    PATH sahte komutlarla doldurulur; böylece ``usermod``/``getent``/``id``
    davranışı root olmadan istenildiği gibi kurgulanabilir.
    """
    directory = tempfile.mkdtemp(prefix="dpibypass-installer-")
    bindir = os.path.join(directory, "bin")
    os.makedirs(bindir)
    for name, body in stubs.items():
        path = os.path.join(bindir, name)
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("#!/usr/bin/env bash\n" + body + "\n")
        os.chmod(path, 0o755)
    environment = dict(os.environ)
    environment.update({
        "PATH": bindir + os.pathsep + "/usr/bin:/bin",
        "DPI_BYPASS_LIB_ONLY": "1",
        "NO_COLOR": "1",
    })
    environment.update(env or {})
    return subprocess.run(
        ["bash", "-c", f'. "{INSTALL_SH}"\n{script}\n'],
        capture_output=True, text=True, env=environment, timeout=60)


class TestInstallerGroupSetup(unittest.TestCase):
    """install.sh setup_group(): usermod hatası asla başarı gösterilmemeli."""

    BASE_STUBS = {
        "getent": 'case "$2" in dpi-bypass) echo "dpi-bypass:x:970:"; exit 0;; '
                  'esac; exit 2',
        "groupadd": "exit 0",
        "id": 'if [ "$1" = "-nG" ]; then echo "ayse wheel"; exit 0; fi; '
              'if [ "$1" = "-nu" ]; then echo ayse; exit 0; fi; '
              'if [ "$1" = "-u" ]; then echo 1000; exit 0; fi; exit 0',
        "logname": "echo ayse",
        "who": "echo 'ayse tty1'",
        "loginctl": "exit 1",
        "usermod": "exit 0",
        "stat": "echo ?",
        "systemctl": "exit 1",
    }

    def stubs(self, **overrides) -> dict:
        merged = dict(self.BASE_STUBS)
        merged.update(overrides)
        return merged

    def run_setup(self, **overrides) -> subprocess.CompletedProcess:
        return run_installer_function(
            'setup_group || true\n'
            'echo "GROUP_READY=$GROUP_READY"\n'
            'echo "GROUP_MEMBER_OK=$GROUP_MEMBER_OK"\n'
            'echo "INSTALL_USER=$INSTALL_USER"\n',
            self.stubs(**overrides))

    def test_successful_add_is_verified_before_reporting_success(self):
        # usermod gerçekten üyeliği değiştirsin: önce yok, sonra var.
        marker = os.path.join(tempfile.mkdtemp(), "added")
        result = self.run_setup(
            usermod=f'touch "{marker}"; exit 0',
            id='if [ "$1" = "-nG" ]; then '
               f'if [ -f "{marker}" ]; then echo "ayse wheel dpi-bypass"; '
               'else echo "ayse wheel"; fi; exit 0; fi; '
               'if [ "$1" = "-nu" ]; then echo ayse; fi; exit 0')
        self.assertIn("GROUP_MEMBER_OK=1", result.stdout)
        self.assertIn("INSTALL_USER=ayse", result.stdout)
        self.assertIn("grubuna eklendi ve doğrulandı", result.stdout)

    def test_usermod_failure_is_not_reported_as_success(self):
        """Asıl hata buydu: '|| true' hatayı yutup 'eklendi' diyordu."""
        result = self.run_setup(usermod='echo "usermod: hata" >&2; exit 1')
        self.assertIn("GROUP_MEMBER_OK=0", result.stdout)
        self.assertNotIn("grubuna eklendi ve doğrulandı", result.stdout)
        self.assertIn("usermod başarısız", result.stdout)
        self.assertIn("çıkış kodu 1", result.stdout)

    def test_silent_usermod_that_does_not_actually_add_is_caught(self):
        """usermod 0 dönse bile üyelik veritabanından yeniden okunur."""
        result = self.run_setup(usermod="exit 0")   # id -nG hâlâ grubu vermiyor
        self.assertIn("GROUP_MEMBER_OK=0", result.stdout)
        self.assertIn("hâlâ", result.stdout)

    def test_missing_usermod_binary_is_reported(self):
        stubs = self.stubs()
        del stubs["usermod"]
        result = run_installer_function(
            'setup_group || true\necho "GROUP_MEMBER_OK=$GROUP_MEMBER_OK"\n',
            stubs)
        self.assertIn("GROUP_MEMBER_OK=0", result.stdout)
        self.assertIn("usermod bulunamadı", result.stdout)

    def test_group_creation_failure_is_not_swallowed(self):
        result = self.run_setup(
            getent="exit 2", groupadd='echo "groupadd: hata" >&2; exit 1')
        self.assertIn("GROUP_READY=0", result.stdout)
        self.assertIn("grubu oluşturulamadı", result.stdout)

    def test_group_created_but_invisible_is_reported(self):
        result = self.run_setup(getent="exit 2", groupadd="exit 0")
        self.assertIn("GROUP_READY=0", result.stdout)
        self.assertIn("görünmüyor", result.stdout)

    def test_already_a_member_is_a_no_op_success(self):
        result = self.run_setup(
            id='if [ "$1" = "-nG" ]; then echo "ayse dpi-bypass"; exit 0; fi; '
               'if [ "$1" = "-nu" ]; then echo ayse; fi; exit 0',
            usermod='echo "usermod çalışmamalıydı" >&2; exit 1')
        self.assertIn("GROUP_MEMBER_OK=1", result.stdout)
        self.assertIn("zaten", result.stdout)

    def test_root_is_never_the_target_user(self):
        result = run_installer_function(
            'setup_group || true\necho "INSTALL_USER=$INSTALL_USER"\n',
            self.stubs(logname="echo root", who="echo 'root tty1'",
                       id='if [ "$1" = "-nu" ]; then echo root; exit 0; fi; '
                          'exit 1'),
            env={"SUDO_USER": "root"})
        self.assertNotIn("INSTALL_USER=root", result.stdout)

    def test_sudo_user_is_preferred(self):
        result = run_installer_function(
            'echo "USER=$(detect_desktop_user)"\n',
            self.stubs(), env={"SUDO_USER": "mehmet"})
        self.assertIn("USER=mehmet", result.stdout)

    def test_nss_only_membership_is_accepted(self):
        """LDAP kullanıcısı /etc/group'ta yok ama 'id -nG' onu gösterir."""
        result = run_installer_function(
            'if user_is_member ayse dpi-bypass; then echo MEMBER; '
            'else echo NOT; fi\n',
            self.stubs(
                id='if [ "$1" = "-nG" ]; then echo "ayse dpi-bypass"; exit 0; fi',
                getent='echo "dpi-bypass:x:970:"; exit 0'))
        self.assertIn("MEMBER", result.stdout)

    def test_etc_group_membership_is_accepted_when_id_is_stale(self):
        result = run_installer_function(
            'if user_is_member ayse dpi-bypass; then echo MEMBER; '
            'else echo NOT; fi\n',
            self.stubs(
                id='if [ "$1" = "-nG" ]; then echo "ayse wheel"; exit 0; fi',
                getent='echo "dpi-bypass:x:970:ayse"; exit 0'))
        self.assertIn("MEMBER", result.stdout)

    def test_membership_check_survives_a_long_group_list(self):
        """grep -q + pipefail tuzağı: uzun çıktıda SIGPIPE ile bozulmamalı."""
        many = " ".join(f"grup{index}" for index in range(400))
        result = run_installer_function(
            'if user_is_member ayse dpi-bypass; then echo MEMBER; '
            'else echo NOT; fi\n',
            self.stubs(
                id=f'if [ "$1" = "-nG" ]; then echo "{many} dpi-bypass"; '
                   'exit 0; fi',
                getent='echo "dpi-bypass:x:970:"; exit 0'))
        self.assertIn("MEMBER", result.stdout)

    def test_partial_group_name_does_not_count_as_membership(self):
        result = run_installer_function(
            'if user_is_member ayse dpi-bypass; then echo MEMBER; '
            'else echo NOT; fi\n',
            self.stubs(
                id='if [ "$1" = "-nG" ]; then echo "ayse dpi-bypass-admin"; '
                   'exit 0; fi',
                getent='echo "dpi-bypass:x:970:ayseb"; exit 0'))
        self.assertIn("NOT", result.stdout)


class TestInstallerVerification(unittest.TestCase):
    """Kurulum sonu sağlık kontrolü: eksik varken 'KURULDU' yazılmamalı."""

    def run_verify(self, script_prefix: str, stubs: dict,
                   env: dict | None = None) -> subprocess.CompletedProcess:
        return run_installer_function(
            script_prefix + "\nverify_installation\nfinal_message\n",
            stubs, env)

    def missing_socket(self) -> str:
        """Var olmayan bir soket yolu — gerçek /run durumundan bağımsız."""
        return os.path.join(tempfile.mkdtemp(), "daemon.sock")

    def test_healthy_installation_prints_success(self):
        directory = tempfile.mkdtemp()
        socket_path = os.path.join(directory, "daemon.sock")
        import socket as socket_module
        server = socket_module.socket(socket_module.AF_UNIX,
                                      socket_module.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(socket_path)
        result = self.run_verify(
            'GROUP_READY=1\nGROUP_MEMBER_OK=1\nINSTALL_USER=ayse\n',
            {"systemctl": "exit 0",
             "stat": 'if [ "$2" = "%G" ]; then echo dpi-bypass; else echo 660; fi'},
            env={"DPI_BYPASS_SOCKET": socket_path})
        self.assertIn("KURULDU:", result.stdout)
        self.assertNotIn("EKSİKLER VAR", result.stdout)

    def test_wrong_socket_group_blocks_the_success_banner(self):
        directory = tempfile.mkdtemp()
        socket_path = os.path.join(directory, "daemon.sock")
        import socket as socket_module
        server = socket_module.socket(socket_module.AF_UNIX,
                                      socket_module.SOCK_STREAM)
        self.addCleanup(server.close)
        server.bind(socket_path)
        result = self.run_verify(
            'GROUP_READY=1\nGROUP_MEMBER_OK=1\nINSTALL_USER=ayse\n',
            {"systemctl": "exit 0",
             "stat": 'if [ "$2" = "%G" ]; then echo root; else echo 600; fi'},
            env={"DPI_BYPASS_SOCKET": socket_path})
        self.assertNotIn("KURULDU:", result.stdout)
        self.assertIn("Soket grubu 'root'", result.stdout)
        self.assertIn("Soket izni 0600", result.stdout)

    def test_failed_group_membership_blocks_the_success_banner(self):
        result = self.run_verify(
            'GROUP_READY=1\nGROUP_MEMBER_OK=0\nINSTALL_USER=ayse\n',
            {"systemctl": "exit 1", "stat": "echo ?", "sleep": "exit 0"},
            env={"DPI_BYPASS_SOCKET": self.missing_socket()})
        self.assertNotIn("KURULDU:", result.stdout)
        self.assertIn("EKSİKLER VAR", result.stdout)
        self.assertIn("grubuna eklenemedi", result.stdout)

    def test_missing_socket_blocks_the_success_banner(self):
        result = self.run_verify(
            'GROUP_READY=1\nGROUP_MEMBER_OK=1\nINSTALL_USER=ayse\n',
            {"systemctl": "exit 0", "stat": "echo ?", "sleep": "exit 0"},
            env={"DPI_BYPASS_SOCKET": self.missing_socket()})
        self.assertNotIn("KURULDU:", result.stdout)
        self.assertIn("soketi oluşmadı", result.stdout)

    def test_missing_group_blocks_the_success_banner(self):
        result = self.run_verify(
            'GROUP_READY=0\nGROUP_MEMBER_OK=0\nINSTALL_USER=\n',
            {"systemctl": "exit 1", "stat": "echo ?", "sleep": "exit 0"},
            env={"DPI_BYPASS_SOCKET": self.missing_socket()})
        self.assertNotIn("KURULDU:", result.stdout)
        self.assertIn("grubu yok", result.stdout)


class TestAccessHelper(unittest.TestCase):
    """pkexec yardımcısı: dar kapsamlı, argümansız, kimliği pkexec belirler."""

    HELPER = os.path.join(REPO_ROOT, "bin", "dpi-bypass-access-helper")

    def run_helper(self, args=(), env=None) -> subprocess.CompletedProcess:
        environment = dict(os.environ)
        environment.pop("PKEXEC_UID", None)
        environment.update(env or {})
        return subprocess.run([sys.executable, self.HELPER, *args],
                              capture_output=True, text=True, env=environment,
                              timeout=30)

    def test_helper_takes_no_arguments(self):
        result = self.run_helper(["wheel"], env={"PKEXEC_UID": "1000"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("argüman almaz", result.stderr)

    def test_helper_refuses_to_run_without_root(self):
        if os.geteuid() == 0:
            self.skipTest("root olarak çalışıyor")
        result = self.run_helper(env={"PKEXEC_UID": "1000"})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root", result.stderr)

    def test_helper_never_targets_root(self):
        with open(self.HELPER, encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("if uid == 0:", source)
        # Grup adı sabit; çağıran taraf seçemez.
        self.assertIn('GROUP = "dpi-bypass"', source)
        self.assertNotIn("shell=True", source)


if __name__ == "__main__":
    unittest.main(verbosity=2)
