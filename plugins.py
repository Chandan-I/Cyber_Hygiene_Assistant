# ------------------------- plugins.py -------------------------
#Remove Linux. Exclusively made for windows.
"""
Improved plugins.py:
- More robust Windows checks for antivirus, firewall and updates.
- Better error handling and clearer evidence fields.
- Fixed Auto-Login registry path typo (Winlogon).
- Uses run_cmd and helper detection functions (works without changing run_cmd signature).

Note: These checks use best-effort OS commands and PowerShell WMI where available.
They still depend on running with appropriate privileges for the most accurate results
(Administrator on Windows) — the code will set evidence when insufficient privileges
are detected.
"""

import re
import psutil
from datetime import datetime
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from utils import run_cmd, service_running_windows, registry_get_string, is_admin
from config import IS_WINDOWS

STATUS_PASS = "PASS"
STATUS_WARN = "WARN"
STATUS_FAIL = "FAIL"
STATUS_SKIPPED = "SKIPPED"

@dataclass
class CheckResult:
    id: str
    label: str
    status: str
    score: int
    evidence: Dict[str, Any]
    advice: str
    weight: int

    def to_row(self):
        return (self.label, self.status, str(self.score))

class CheckPlugin:
    id = "base"
    label = "Base Check"
    weight = 10
    def run(self) -> CheckResult:
        raise NotImplementedError

# ---------------- Helper functions ----------------
def _powershell(cmd: str) -> str:
    """Run a PowerShell command on Windows and return output (best-effort)."""
    try:
        out = run_cmd(["powershell", "-NoProfile", "-Command", cmd], timeout=15)
        return out
    except Exception:
        return ""

def detect_installed_antivirus_windows() -> List[str]:
    """Return list of AV product names found via SecurityCenter2 WMI and common process names."""
    prods = []
    try:
        # SecurityCenter2 query (Windows 8+)
        out = _powershell("Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct | Select-Object -ExpandProperty displayName")
        for line in out.splitlines():
            line = line.strip()
            if line:
                prods.append(line)
    except Exception:
        pass
    # Fallback: look for common AV processes/services
    try:
        procs = [p.name().lower() for p in psutil.process_iter(attrs=['name']) if p.name()]
        known = [
            'msmpeng.exe',  # Windows Defender
            'avp.exe',      # Kaspersky
            'mcshield.exe', 'mcsysmon.exe', 'f-secure',
            'savservice.exe', 'savservice', # Symantec
            'avg', 'avast', 'nod32', 'egui', 'clamd', 'clamav'
        ]
        for k in known:
            if any(k in p for p in procs):
                prods.append(k)
    except Exception:
        pass
    # dedupe and return
    seen = []
    for p in prods:
        if p and p not in seen:
            seen.append(p)
    return seen

import re
from typing import Dict, Any
from utils import run_cmd  # make sure run_cmd is already defined

def detect_firewall_windows() -> Dict[str, Any]:
    """Return dict with firewall profile states and any third-party firewall detected."""
    info: Dict[str, Any] = {"profiles": {}, "third_party": []}
    try:
        # --- First: Try PowerShell for profile status ---
        ps_out = run_cmd([
            "powershell", "-Command",
            "Get-NetFirewallProfile | Select-Object -Property Name, Enabled"
        ], timeout=8)
        profiles: Dict[str, bool] = {}
        for line in ps_out.splitlines():
            if not line.strip() or line.strip().startswith("Name"):
                continue
            parts = line.split()
            if len(parts) >= 2:
                name, enabled = parts[0], parts[-1]
                profiles[name] = enabled.lower() in ("true", "yes", "1")
        if profiles:
            info["profiles"] = profiles

        # --- Query SecurityCenter2 for third-party firewall ---
        try:
            sc_out = run_cmd([
                "powershell", "-Command",
                "Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName FirewallProduct | "
                "Select-Object -ExpandProperty displayName"
            ], timeout=8)
            for l in sc_out.splitlines():
                l = l.strip()
                if l:
                    info["third_party"].append(l)
        except Exception:
            pass

        # --- Fallback: netsh if PowerShell fails ---
        if not info["profiles"]:
            out = run_cmd(["netsh", "advfirewall", "show", "allprofiles"], timeout=12)
            for profile in ("Domain Profile", "Private Profile", "Public Profile"):
                m = re.search(rf"{re.escape(profile)}[\s\S]*?State\s*:\s*(ON|OFF)", out, re.IGNORECASE)
                if m:
                    info['profiles'][profile] = (m.group(1).upper() == 'ON')
    except Exception as e:
        info["error"] = str(e)

    return info

def windows_last_update_info() -> Optional[Dict[str, Any]]:
    """Return info about recent installed updates (best-effort)."""
    try:
        out = run_cmd(["wmic", "qfe", "get", "HotFixID,InstalledOn,Description"], timeout=12)
        if out:
            lines = [l.strip() for l in out.splitlines() if l.strip()]
            if len(lines) >= 2:
                # take last non-header line
                last = lines[-1]
                return {"raw_sample": last}
    except Exception:
        pass
    # Fallback: try PowerShell Get-HotFix
    try:
        ps = _powershell("Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1 | Format-List -Property Description,InstalledOn,HotFixID")
        if ps:
            return {"powershell_sample": ps.strip()}
    except Exception:
        pass
    return None

# ---------------- Plugins ----------------
class FirewallStatusCheck(CheckPlugin):
    id = "firewall_status"
    label = "Firewall Status"
    weight = 15

    def run(self) -> CheckResult:
        evidence: Dict[str, Any] = {"is_admin": is_admin()}
        try:
            if IS_WINDOWS:
                info = detect_firewall_windows() or {}
                evidence.update(info)

                # Ensure profiles dict exists
                profiles = info.get('profiles') or {}

                from utils import service_running_windows
                firewall_service = service_running_windows("MpsSvc")  # Windows Firewall service
                evidence['service_status'] = firewall_service

                # Extract profile states
                public_on = profiles.get("Public", False)
                private_on = profiles.get("Private", False)
                domain_on = profiles.get("Domain", False)

                # Weighted score
                score = (50 if public_on else 0) + (30 if private_on else 0) + (20 if domain_on else 0)

                # Advice & status
                if score == 100:
                    advice = "Windows Firewall is enabled for all profiles."
                    status = STATUS_PASS
                elif score == 0:
                    advice = "Windows Firewall is disabled on all profiles."
                    status = STATUS_FAIL
                else:
                    off_profiles = [p for p, enabled in profiles.items() if not enabled and p.strip() and p != "----"]
                    advice = f"Windows Firewall is partially enabled (Score={score}). Profiles OFF: {', '.join(off_profiles)}"
                    status = STATUS_WARN

                # Fallback if service running but profiles unclear
                if firewall_service is True and score == 0:
                    score = 0
                    advice = "Windows Firewall service is running, but DOMAIN, PUBLIC AND PRIVATE profiles are disabled."
                    status = STATUS_FAIL
            else:
                status, score, advice = STATUS_SKIPPED, 0, "Firewall check not supported on this OS."


        except Exception as e:
            status, score, advice = STATUS_WARN, 50, f"Firewall check error: {e}"
            evidence['error'] = str(e)

        return CheckResult(self.id, self.label, status, score, evidence, advice, self.weight)

class AntivirusStatusCheck(CheckPlugin):
    id = "antivirus_status"
    label = "Antivirus Status"
    weight = 15

    def run(self) -> CheckResult:
        evidence: Dict[str, Any] = {"is_admin": is_admin()}
        try:
            if IS_WINDOWS:
                prods = detect_installed_antivirus_windows()
                evidence['detected_products'] = prods
                if prods:
                    status, score, advice = STATUS_PASS, 100, "Antivirus products detected: %s" % (', '.join(prods))
                else:
                    # also check Windows Security Center state via PowerShell
                    ps = _powershell("Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Select-Object -ExpandProperty displayName")
                    if ps and ps.strip():
                        evidence['security_center'] = ps.strip()
                        status, score, advice = STATUS_PASS, 100, "Antivirus reported by Security Center."
                    else:
                        status, score, advice = STATUS_WARN, 30, "No antivirus product detected via heuristics. Ensure an AV is installed and running."
            else:
                status, score, advice = STATUS_SKIPPED, 0, "Antivirus check unsupported on this OS in MVP."
        except Exception as e:
            status, score, advice = STATUS_WARN, 50, f"Antivirus check error: {e}"
            evidence['error'] = str(e)
        return CheckResult(self.id, self.label, status, score, evidence, advice, self.weight)

class OSUpdatesCheck(CheckPlugin):
    id = "os_updates"
    label = "OS Update Status"
    weight = 12

    def run(self) -> CheckResult:
        evidence: Dict[str, Any] = {"is_admin": is_admin()}
        try:
            if IS_WINDOWS:
                # check update service and last installed hotfix
                wsvc = service_running_windows("wuauserv")
                evidence['wuauserv_running'] = wsvc
                last = windows_last_update_info()
                evidence['last_update_sample'] = last
                if wsvc and last:
                    status, score, advice = STATUS_PASS, 100, "Windows Update service running and recent updates present (see evidence)."
                elif wsvc and not last:
                    status, score, advice = STATUS_WARN, 70, "Windows Update service is running but could not determine recent updates."
                else:
                    status, score, advice = STATUS_WARN, 40, "Windows Update service not running or could not be queried. Ensure updates are enabled."
            else:
                status, score, advice = STATUS_SKIPPED, 0, "OS update check unsupported on this OS."
        except Exception as e:
            status, score, advice = STATUS_WARN, 50, f"OS update check error: {e}"
            evidence['error'] = str(e)
        return CheckResult(self.id, self.label, status, score, evidence, advice, self.weight)

class OpenPortsCheck(CheckPlugin):
    id = "open_ports"
    label = "Open Ports (Listening)"
    weight = 10

    def run(self) -> CheckResult:
        evidence: Dict[str, Any] = {"is_admin": is_admin(), "listening": []}
        try:
            cons = psutil.net_connections(kind='inet')
            # If empty and not admin, indicate likely insufficient permissions
            if not cons and not evidence['is_admin']:
                evidence['note'] = 'No net_connections returned; run as Administrator/root for full results.'
            for c in cons:
                if getattr(c, 'status', None) == psutil.CONN_LISTEN:
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "?"
                    pid = c.pid
                    proc_name = None
                    services = []
                    try:
                        if pid:
                            proc = psutil.Process(pid)
                            proc_name = proc.name()
                            # fetch Windows service info (tasklist /svc)
                            if IS_WINDOWS:
                                try:
                                    import subprocess
                                    out = run_cmd(["tasklist", "/svc", "/FI", f"PID eq {pid}"], timeout=8)
                                    services.append(out.strip())
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    evidence['listening'].append({
                        'addr': laddr,
                        'pid': pid,
                        'proc': proc_name,
                        'services': services
                    })
            if evidence['listening']:
                status, score, advice = STATUS_WARN, 60, "Open listening ports detected. Review and close unused ones. Run as admin for better details."
            else:
                status, score, advice = STATUS_PASS, 100, "No open listening ports detected (or requires privileged enumeration)."
        except Exception as e:
            status, score, advice = STATUS_WARN, 50, f"Could not enumerate connections: {e}"
            evidence['error'] = str(e)
        return CheckResult(self.id, self.label, status, score, evidence, advice, self.weight)

class AutoLoginCheck(CheckPlugin):
    id = "auto_login"
    label = "Auto-Login Disabled"
    weight = 8

    def run(self) -> CheckResult:
        evidence: Dict[str, Any] = {}
        try:
            if IS_WINDOWS:
                # FIXED: Correct registry key "Winlogon"
                val = registry_get_string(r"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "AutoAdminLogon")
                evidence["AutoAdminLogin"] = val
                is_disabled = (val is None) or (val == "0")
                status = STATUS_PASS if is_disabled else STATUS_FAIL
                score = 100 if is_disabled else 0
                advice = "Disable automatic login to require a password at sign-in (use Netplwiz or registry)."
            else:
                status, score, advice = STATUS_SKIPPED, 0, "Auto-login check supported for Windows in MVP."
        except Exception as e:
            status, score, advice = STATUS_WARN, 50, f"Auto-login check error: {e}"
            evidence['error'] = str(e)
        return CheckResult(self.id, self.label, status, score, evidence, advice, self.weight)

class WifiSecurityCheck(CheckPlugin):
    id = "wifi_security"
    label = "Wi-Fi Security"
    weight = 8

    
    def run(self) -> CheckResult:
        evidence: Dict[str, Any] = {}
        try:
            if IS_WINDOWS:
                out = run_cmd(["netsh", "wlan", "show", "interfaces"], timeout=8)

                # Parse and clean lines
                neat_lines = []
                for line in out.splitlines():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        key = key.strip()
                        value = value.strip()
                        if key and value:
                            neat_lines.append(f"{key:<25}: {value}")

                evidence["raw"] = "\n".join(neat_lines)

                # --- Updated logic starts here ---
                if not out.strip() or "State" in out and "disconnected" in out.lower():
                    # No Wi-Fi connection
                    status, score, advice = STATUS_PASS, 100, "Not connected to any Wi-Fi network."
                else:
                    strong = ("WPA2" in out.upper()) or ("WPA3" in out.upper())
                    weak = ("WEP" in out.upper()) or ("OPEN" in out.upper())

                    if weak:
                        status, score, advice = STATUS_FAIL, 0, "Weak Wi-Fi security (OPEN/WEP). Switch router to WPA2 or WPA3 with a strong password."
                    elif strong:
                        status, score, advice = STATUS_PASS, 100, "Secure Wi-Fi detected (WPA2/WPA3). Keep a strong passphrase."
                    else:
                        status, score, advice = STATUS_WARN, 60, "Could not determine Wi-Fi cipher/auth. Ensure WPA2/WPA3 is enabled."
                # --- Updated logic ends here ---

            else:
                status, score, advice = STATUS_SKIPPED, 0, "Wi-Fi check unsupported on this OS in MVP."

        except Exception as e:
            status, score, advice = STATUS_WARN, 50, f"Wi-Fi check error: {e}"
            evidence['error'] = str(e)

        return CheckResult(self.id, self.label, status, score, evidence, advice, self.weight)

# ------------------------- end plugins.py -------------------------