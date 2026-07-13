#!/usr/bin/env python3
"""torwall - a system-wide transparent Tor firewall.

torwall redirects every outbound TCP connection and DNS query through Tor and
acts as a kill-switch: if tor is not running, non-Tor traffic is blocked rather
than leaking. IPv6 is disabled by default to avoid a common deanonymization
vector, and no host-identifying information is written to the tor configuration.

Identity hardening:
  By default --load also assigns a random MAC address and a random hostname,
  and restores both automatically on exit (Ctrl+C, normal exit, or --flush).
  Use --keep-identity (or --no-mac / --no-hostname) to leave them untouched,
  e.g. when you are on a trusted home network and reach the box over SSH.
"""

from __future__ import annotations

import argparse
import atexit
import json
import logging
import os
import random
import shutil
import signal
import socket
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from time import sleep, monotonic

LOG = logging.getLogger("torwall")

TOR_USERS = ("debian-tor", "tor", "_tor", "toranon")
TORRC_PATHS = ("/etc/tor/torrc", "/usr/local/etc/tor/torrc")

# Where the original MAC addresses and hostname are stashed so they can be
# restored later. Lives on a tmpfs so it does not survive a reboot.
IDENTITY_STATE = "/var/run/torwall_identity.json"

# A neutral marker so the script can find and update its own block without
# embedding the script name, hostname, user or any other identifying detail.
TORRC_MARKER = "## transparent proxy"

TORRC_BLOCK = """
{marker}
VirtualAddrNetwork {virtual_net}
AutomapHostsOnResolve 1
TransPort {trans_port}
DNSPort {dns_port}
"""

BANNER = r"""
     _ _____                 ___
    | |___ /__  ___ __ ___  / _ \ ___
  __| | |_ \ \/ / '_ ` _ \ | | | / __|
 / _` |___) >  <| | | | | || |_| \__ \
 \__,_|____/_/\_\_| |_| |_| \___/|___/
"""


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    CYAN = "\033[96m"


def show_banner() -> None:
    print(f"{Color.BOLD}{Color.RED}{BANNER}{Color.RESET}")


def ok(msg: str) -> None:
    print(f" [{Color.GREEN}+{Color.RESET}] {msg}")


def info(msg: str) -> None:
    print(f" [{Color.GREEN}*{Color.RESET}] {msg}")


def warn(msg: str) -> None:
    print(f" [{Color.YELLOW}!{Color.RESET}] {msg}")


def error(msg: str) -> None:
    print(f" [{Color.RED}!{Color.RESET}] {msg}", file=sys.stderr)


def run(cmd: list[str], check: bool = True, quiet: bool = False) -> subprocess.CompletedProcess:
    kwargs: dict = {"text": True}
    if quiet:
        kwargs["stdout"] = subprocess.DEVNULL
        kwargs["stderr"] = subprocess.DEVNULL
    else:
        kwargs["capture_output"] = True
    return subprocess.run(cmd, check=check, **kwargs)


class ServiceManager:
    """Hide the difference between systemd and SysV init."""

    def __init__(self) -> None:
        if shutil.which("systemctl"):
            self._kind = "systemd"
        elif shutil.which("service"):
            self._kind = "service"
        else:
            raise RuntimeError("no supported service manager found (systemctl/service)")

    def restart(self, name: str) -> None:
        cmd = (["systemctl", "restart", name] if self._kind == "systemd"
               else ["service", name, "restart"])
        run(cmd, quiet=True)

    def is_active(self, name: str) -> bool:
        if self._kind == "systemd":
            result = run(["systemctl", "is-active", name], check=False)
            return result.stdout.strip() == "active"
        result = run(["service", name, "status"], check=False)
        return result.returncode == 0


# -- identity (MAC / hostname) --------------------------------------------

class Identity:
    """Randomize the MAC addresses and hostname, remembering the originals.

    The original values are written to IDENTITY_STATE the first time something
    is changed, and read back from there on restore. This keeps restore working
    even across a fresh invocation of the script (e.g. `torwall -f`).
    """

    def __init__(self) -> None:
        self._state = self._read_state()

    @staticmethod
    def _read_state() -> dict:
        try:
            with open(IDENTITY_STATE, "r") as fh:
                return json.load(fh)
        except (FileNotFoundError, ValueError):
            return {}

    def _write_state(self) -> None:
        os.makedirs(os.path.dirname(IDENTITY_STATE), exist_ok=True)
        with open(IDENTITY_STATE, "w") as fh:
            json.dump(self._state, fh)

    @staticmethod
    def _interfaces() -> list[tuple[str, str]]:
        # returns (iface, current_mac) for every non-loopback link
        result = run(["ip", "-o", "link", "show"], check=False)
        ifaces: list[tuple[str, str]] = []
        for line in result.stdout.splitlines():
            parts = line.split(": ")
            if len(parts) < 2:
                continue
            iface = parts[1].split("@")[0]
            if iface == "lo":
                continue
            mac = ""
            tokens = line.split()
            if "link/ether" in tokens:
                mac = tokens[tokens.index("link/ether") + 1]
            ifaces.append((iface, mac))
        return ifaces

    def randomize_mac(self) -> None:
        if not shutil.which("ip"):
            error("'ip' command not found, cannot change MAC")
            return
        saved = self._state.setdefault("mac", {})
        for iface, current in self._interfaces():
            if current and iface not in saved:
                saved[iface] = current
            octets = [0x02, *(random.randint(0x00, 0xff) for _ in range(5))]
            mac = ":".join(f"{o:02x}" for o in octets)
            try:
                run(["ip", "link", "set", iface, "down"])
                run(["ip", "link", "set", iface, "address", mac])
                run(["ip", "link", "set", iface, "up"])
                ok(f"{iface} MAC set to {mac}")
            except subprocess.CalledProcessError:
                error(f"failed to change MAC on {iface}")
        self._write_state()

    def randomize_hostname(self) -> None:
        if not shutil.which("hostnamectl"):
            error("'hostnamectl' not found, cannot change hostname")
            return
        if "hostname" not in self._state:
            current = socket.gethostname()
            self._state["hostname"] = current
        name = "host-" + "".join(random.choices("0123456789abcdef", k=8))
        try:
            run(["hostnamectl", "set-hostname", name])
            ok(f"hostname set to {name}")
            self._write_state()
        except subprocess.CalledProcessError:
            error("failed to change hostname")

    def restore(self) -> None:
        state = self._read_state()
        if not state:
            return
        for iface, mac in state.get("mac", {}).items():
            try:
                run(["ip", "link", "set", iface, "down"])
                run(["ip", "link", "set", iface, "address", mac])
                run(["ip", "link", "set", iface, "up"])
                ok(f"{iface} MAC restored to {mac}")
            except subprocess.CalledProcessError:
                error(f"failed to restore MAC on {iface}")
        original_host = state.get("hostname")
        if original_host and shutil.which("hostnamectl"):
            try:
                run(["hostnamectl", "set-hostname", original_host])
                ok(f"hostname restored to {original_host}")
            except subprocess.CalledProcessError:
                error("failed to restore hostname")
        try:
            os.remove(IDENTITY_STATE)
        except FileNotFoundError:
            pass
        self._state = {}


@dataclass
class Config:
    trans_port: str = "9040"
    dns_port: str = "53"
    virtual_net: str = "10.0.0.0/10"
    loopback: str = "127.0.0.1"
    non_tor: list[str] = field(default_factory=lambda: [
        "127.0.0.0/8",
        "192.168.0.0/16",
        "172.16.0.0/12",
        "10.192.0.0/10",
    ])


class TorWall:
    def __init__(self, config: Config | None = None) -> None:
        self.cfg = config or Config()
        self.tor_uid = self._resolve_tor_uid()
        self.torrc = self._resolve_torrc()
        self.services = ServiceManager()

    @staticmethod
    def _resolve_tor_uid() -> str:
        for user in TOR_USERS:
            result = run(["id", "-ur", user], check=False)
            if result.returncode == 0:
                return result.stdout.strip()
        raise RuntimeError("tor system user not found; is the tor package installed?")

    @staticmethod
    def _resolve_torrc() -> str:
        for path in TORRC_PATHS:
            if os.path.isfile(path):
                return path
        return TORRC_PATHS[0]

    # -- torrc -------------------------------------------------------------

    def ensure_torrc(self) -> None:
        if not os.path.isfile(self.torrc):
            warn(f"{self.torrc} not found, skipping torrc update")
            return
        with open(self.torrc, "r") as conf:
            if TORRC_MARKER in conf.read():
                return
        block = TORRC_BLOCK.format(
            marker=TORRC_MARKER,
            virtual_net=self.cfg.virtual_net,
            trans_port=self.cfg.trans_port,
            dns_port=self.cfg.dns_port,
        )
        with open(self.torrc, "a") as conf:
            conf.write(block)
        ok("Updated torrc with transparent proxy settings")

    # -- iptables ----------------------------------------------------------

    @staticmethod
    def _ipt(args: list[str], v6: bool = False) -> None:
        binary = "ip6tables" if v6 else "iptables"
        run([binary, *args], quiet=True)

    def flush(self) -> None:
        for v6 in (False, True):
            binary = "ip6tables" if v6 else "iptables"
            if not shutil.which(binary):
                continue
            self._ipt(["-F"], v6)
            self._ipt(["-t", "nat", "-F"], v6)

    def block_ipv6(self) -> None:
        if not shutil.which("ip6tables"):
            return
        for chain in ("INPUT", "OUTPUT", "FORWARD"):
            self._ipt(["-P", chain, "DROP"], v6=True)
        ok("IPv6 traffic blocked")

    def load(self) -> None:
        self.flush()
        self.block_ipv6()
        c = self.cfg

        for flags in ("ACK,FIN", "ACK,RST"):
            self._ipt(["-I", "OUTPUT", "!", "-o", "lo", "!", "-d", c.loopback,
                       "!", "-s", c.loopback, "-p", "tcp", "-m", "tcp",
                       "--tcp-flags", flags, flags, "-j", "DROP"])

        # nat: tor's own traffic returns, DNS and TCP go to tor.
        self._ipt(["-t", "nat", "-A", "OUTPUT", "-m", "owner",
                   "--uid-owner", self.tor_uid, "-j", "RETURN"])
        self._ipt(["-t", "nat", "-A", "OUTPUT", "-p", "udp",
                   "--dport", c.dns_port, "-j", "REDIRECT",
                   "--to-ports", c.dns_port])
        for net in c.non_tor:
            self._ipt(["-t", "nat", "-A", "OUTPUT", "-d", net, "-j", "RETURN"])
        self._ipt(["-t", "nat", "-A", "OUTPUT", "-p", "tcp", "--syn",
                   "-j", "REDIRECT", "--to-ports", c.trans_port])

        # filter: allow established, loopback, local nets, tor; reject the rest.
        self._ipt(["-A", "OUTPUT", "-m", "state", "--state",
                   "ESTABLISHED,RELATED", "-j", "ACCEPT"])
        self._ipt(["-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])
        for net in c.non_tor:
            self._ipt(["-A", "OUTPUT", "-d", net, "-j", "ACCEPT"])
        self._ipt(["-A", "OUTPUT", "-m", "owner", "--uid-owner",
                   self.tor_uid, "-j", "ACCEPT"])
        self._ipt(["-A", "OUTPUT", "-j", "REJECT"])

        try:
            self.services.restart("tor")
        except subprocess.CalledProcessError:
            # Kill-switch stays up: leave the REJECT rules in place so no
            # traffic leaks while tor is down, then surface the failure.
            error("tor failed to restart; firewall left active to prevent leaks")
            raise
        ok(f"torwall status {Color.GREEN}[ON]{Color.RESET}")
        self.get_ip()

    # -- status / ip -------------------------------------------------------

    def status(self) -> None:
        active = self.services.is_active("tor")
        result = run(["iptables", "-S", "OUTPUT"], check=False)
        rules_loaded = "REJECT" in result.stdout
        tor_state = f"{Color.GREEN}running{Color.RESET}" if active \
            else f"{Color.RED}stopped{Color.RESET}"
        fw_state = f"{Color.GREEN}active{Color.RESET}" if rules_loaded \
            else f"{Color.RED}inactive{Color.RESET}"
        info(f"tor: {tor_state}   firewall: {fw_state}")
        if active and rules_loaded:
            self.get_ip()

    def get_ip(self) -> None:
        info("Getting public IP, please wait...")
        public_ip = None
        for _ in range(12):
            try:
                with urllib.request.urlopen(
                    "https://check.torproject.org/api/ip", timeout=10
                ) as resp:
                    public_ip = json.load(resp).get("IP")
                if public_ip:
                    break
            except (urllib.error.URLError, TimeoutError, socket.timeout):
                warn("Still waiting for IP address...")
                sleep(5)
            except ValueError:
                break
        if not public_ip:
            try:
                with urllib.request.urlopen("https://ident.me", timeout=10) as resp:
                    public_ip = resp.read().decode().strip()
            except (urllib.error.URLError, TimeoutError, socket.timeout):
                public_ip = None
        if not public_ip:
            error("Can't get public IP address!")
            return
        ok(f"Your IP is {Color.GREEN}{public_ip}{Color.RESET}")

    def refresh(self) -> None:
        result = run(["pidof", "tor"], check=False)
        pid = result.stdout.strip()
        if not pid:
            error("tor process not found")
            return
        run(["kill", "-HUP", pid])
        self.get_ip()

    def auto_rotate(self, interval: int, identity: "Identity | None" = None,
                    rotate_mac: bool = False, rotate_hostname: bool = False) -> None:
        """Change circuit (and optionally MAC/hostname) every `interval` seconds.

        Runs until interrupted with Ctrl+C. When MAC or hostname rotation is
        enabled the network is briefly torn down, so tor is restarted and given
        a moment to rebuild a circuit before the next IP check.
        """
        info(f"Auto-rotation every {interval}s. Press Ctrl+C to stop.")
        cycle = 0
        try:
            while True:
                cycle += 1
                info(f"--- cycle {cycle} ---")
                if (rotate_mac or rotate_hostname) and identity is not None:
                    if rotate_mac:
                        identity.randomize_mac()
                    if rotate_hostname:
                        identity.randomize_hostname()
                    # The interface bounce drops tor's connections; restart it
                    # and wait for bootstrap before asking for the new IP.
                    try:
                        self.services.restart("tor")
                    except subprocess.CalledProcessError:
                        error("tor failed to restart after network change")
                    sleep(10)
                    self.get_ip()
                else:
                    self.refresh()

                deadline = monotonic() + interval
                while monotonic() < deadline:
                    sleep(min(1.0, deadline - monotonic()))
        except KeyboardInterrupt:
            print()
            warn("Auto-rotation stopped")


# -- cli -------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="torwall",
        description="System-wide transparent Tor firewall and kill-switch",
    )
    p.add_argument("-l", "--load", action="store_true",
                   help="load the firewall and route all traffic through Tor")
    p.add_argument("-f", "--flush", action="store_true",
                   help="flush the rules, restore identity, return to normal")
    p.add_argument("-r", "--refresh", action="store_true",
                   help="request a new circuit and a new exit IP")
    p.add_argument("-i", "--ip", action="store_true",
                   help="print the current public IP address")
    p.add_argument("-s", "--status", action="store_true",
                   help="show tor and firewall status")
    p.add_argument("--auto", nargs="?", type=int, const=180, metavar="SECONDS",
                   help="rotate IP every SECONDS (default 180); "
                        "add --mac/--hostname to also rotate those each cycle")
    p.add_argument("--mac", action="store_true",
                   help="with --auto: also rotate the MAC each cycle")
    p.add_argument("--hostname", action="store_true",
                   help="with --auto: also rotate the hostname each cycle")
    p.add_argument("--no-mac", action="store_true",
                   help="with --load: do not change the MAC address")
    p.add_argument("--no-hostname", action="store_true",
                   help="with --load: do not change the hostname")
    p.add_argument("--keep-identity", action="store_true",
                   help="with --load: change neither MAC nor hostname "
                        "(use on a trusted home/SSH network)")
    return p


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    show_banner()
    parser = build_parser()
    args = parser.parse_args()

    actions = (args.load, args.flush, args.refresh, args.ip, args.status,
               args.auto is not None)
    if not any(actions):
        parser.print_help()
        return 0

    if os.geteuid() != 0:
        error("This script must be run as root.")
        return 1
    if not shutil.which("iptables"):
        error("iptables not found in PATH.")
        return 1

    try:
        wall = TorWall()
    except RuntimeError as err:
        error(str(err))
        return 1

    identity = Identity()

    try:
        if args.load:
            change_mac = not (args.no_mac or args.keep_identity)
            change_hostname = not (args.no_hostname or args.keep_identity)

            if change_mac or change_hostname:
                # Restore the original identity no matter how we exit: a clean
                # return, Ctrl+C, or a TERM from closing the session.
                atexit.register(identity.restore)

                def _on_signal(signum, _frame):
                    print()
                    warn("Signal received, restoring identity...")
                    identity.restore()
                    sys.exit(128 + signum)

                for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
                    signal.signal(sig, _on_signal)

            if change_mac:
                identity.randomize_mac()
            if change_hostname:
                identity.randomize_hostname()
            wall.ensure_torrc()
            wall.load()

            if change_mac or change_hostname:
                info("Identity active. Keep this running; "
                     "press Ctrl+C to restore MAC/hostname and exit.")
                signal.pause()
        elif args.flush:
            wall.flush()
            identity.restore()
            warn(f"torwall status {Color.RED}[OFF]{Color.RESET}")
        elif args.refresh:
            wall.refresh()
        elif args.ip:
            wall.get_ip()
        elif args.status:
            wall.status()
        elif args.auto is not None:
            if args.auto < 10:
                error("interval must be at least 10 seconds")
                return 1
            if args.mac or args.hostname:
                atexit.register(identity.restore)
            wall.auto_rotate(args.auto, identity=identity,
                             rotate_mac=args.mac, rotate_hostname=args.hostname)
            identity.restore()
    except subprocess.CalledProcessError as err:
        error(f"Command failed: {' '.join(err.cmd)}")
        return 1
    except PermissionError as err:
        error(str(err))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
