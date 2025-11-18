import json, socket, threading, platform, os, shutil
from datetime import datetime
from typing import Dict, Any, List
from plugins import CheckResult, CheckPlugin
from config import APP_NAME, APP_VERSION, LAST_SCAN_JSON, DATA_DIR

class ScoringEngine:
    def __init__(self, weights: Dict[str, int]):
        self.weights = weights

    def overall(self, results: List[CheckResult]) -> int:
        total_w, acc = 0, 0
        for r in results:
            w = self.weights.get(r.id, r.weight)
            total_w += w
            acc += r.score * w
        return round(acc / total_w) if total_w else 0

class Orchestrator:
    def __init__(self, plugins: List[CheckPlugin], weights: Dict[str, int]):
        self.plugins = plugins
        self.weights = weights
        self.scorer = ScoringEngine(weights)

    def run_scan(self) -> Dict[str, Any]:
        results: List[CheckResult] = []
        lock = threading.Lock()

        def run_one(p: CheckPlugin):
            try:
                r = p.run()
            except Exception as e:
                r = CheckResult(
                    p.id,
                    p.label,
                    "WARN",
                    50,
                    {"error": str(e)},
                    "Check crashed",
                    p.weight,
                )
            with lock:
                results.append(r)

        threads = [threading.Thread(target=run_one, args=(p,), daemon=True) for p in self.plugins]
        [t.start() for t in threads]
        [t.join(timeout=12) for t in threads]

        for p in self.plugins:
            if not any(r.id == p.id for r in results):
                results.append(
                    CheckResult(
                        p.id, p.label, "WARN", 50, {"timeout": True}, "Timed out.", p.weight
                    )
                )

        overall = self.scorer.overall(results)
        payload = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "app": APP_NAME,
            "version": APP_VERSION,
            "os": platform.platform(),
            "hostname": socket.gethostname(),
            "overall_score": overall,
            "breakdown": [r.__dict__ for r in results],
        }

        try:
            # If a last scan exists, back it up first
            if os.path.exists(LAST_SCAN_JSON):
                prev_file = os.path.join(DATA_DIR, "prev_scan.json")
                shutil.copy(LAST_SCAN_JSON, prev_file)

            # Write the new scan as the current one
            with open(LAST_SCAN_JSON, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
        except Exception as e:
            print(f"[ERROR] Could not save scan report: {e}")

        return payload