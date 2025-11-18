# ------------------------- utils.py -------------------------
"""
Improved utils.py:
    is_admin: helper to detect privileged execution on Windows
"""
import subprocess
import platform
from typing import List, Optional
from config import IS_WINDOWS
import ctypes
import os

def run_cmd(cmd: List[str], timeout: int = 15) -> str:
    """Run a command and return stdout+stderr as a string (best-effort).
    This keeps the previous signature (returns str) so other modules don't break.

    - Captures stderr and appends to the returned text so callers have more information.
    - Returns empty string only if subprocess itself fails to start.
    """
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            shell=False,
            creationflags=subprocess.CREATE_NO_WINDOW  # 👈 hides CMD/PowerShell window
        )
        out = b""
        if proc.stdout:
            out += proc.stdout
        if proc.stderr:
            out += b"\n[stderr]\n" + proc.stderr
        return out.decode(errors='ignore')
    except subprocess.TimeoutExpired as e:
        return f"[timeout after {timeout}s] {str(e)}"
    except FileNotFoundError:
        return ""  # command not found (tool may not be installed)
    except Exception as e:
        return str(e)

def service_running_windows(service_name: str) -> Optional[bool]:
    """Return True if service is running, False if stopped, None if unknown/unavailable.
    Uses sc query and falls back to PowerShell query.
    """
    if not IS_WINDOWS:
        return None
    try:
        out = run_cmd(["sc", "query", service_name], timeout=8)
        if not out:
            # try powershell Get-Service
            out2 = run_cmd(["powershell", "-NoProfile", "-Command", f"(Get-Service -Name {service_name} -ErrorAction SilentlyContinue).Status"], timeout=8)
            if out2 and 'Running' in out2:
                return True
            if out2 and 'Stopped' in out2:
                return False
            return None
        return 'RUNNING' in out
    except Exception:
        return None

def registry_get_string(path: str, name: str) -> Optional[str]:
    if not IS_WINDOWS:
        return None
    try:
        import winreg
        root_map = {
            'HKEY_LOCAL_MACHINE': winreg.HKEY_LOCAL_MACHINE,
            'HKEY_CURRENT_USER': winreg.HKEY_CURRENT_USER,
        }
        root_str, subkey = path.split('\\', 1)
        root = root_map.get(root_str)
        if not root:
            return None
        with winreg.OpenKey(root, subkey) as key:
            val, _ = winreg.QueryValueEx(key, name)
            return str(val)
    except Exception:
        return None

def is_admin() -> bool:
    """Return True if running with elevated privileges (admin/root).
    Works on Windows and *nix.
    """
    try:
        if IS_WINDOWS:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except Exception:
        return False
# ------------------------- end utils.py -------------------------