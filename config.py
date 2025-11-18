import os
import platform
APP_NAME = "Cyber Hygiene Assistant"
APP_VERSION = "6.0.0"
IS_WINDOWS = platform.system().lower() == 'windows'
DATA_DIR = os.path.join(os.path.expanduser("~"), ".cyber_hygiene_assistant")
LAST_SCAN_JSON = os.path.join(DATA_DIR, "last_scan.json")
os.makedirs(DATA_DIR, exist_ok=True)