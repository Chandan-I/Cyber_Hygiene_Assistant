"""
Cyber Hygiene Assistant + Quiz (Version 5 / Enhanced Open Ports)

Exclusively for Windows. Removed Linux Plugins
==================================================================
Enhancements since Version 4:
- Improved Open Ports tab with service hints.
- Added `get_port_hint()` for smarter detection.
- Combined Windows service + process EXE lookups.
- Enhanced security insights for open ports.
- Retains full functionality: Scan, Quiz, Reports.
- Fixed firewall and Wi-Fi data formatting.
- Admin mode for accurate live system info.
"""

import sys
import ctypes
import os

IS_WINDOWS = sys.platform.startswith("win")

# Hide any attached console (even when running as admin)
if IS_WINDOWS:
    try:
        ctypes.windll.kernel32.FreeConsole()
    except Exception:
        pass  # Just in case, don't crash GUI if FreeConsole fails

from gui import App  # import after cleanup to avoid flicker

if __name__ == "__main__":
    app = App()
    app.mainloop()
