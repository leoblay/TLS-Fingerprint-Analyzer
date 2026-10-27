"""Flask dashboard and experiment orchestrator for local TLS fingerprinting."""

from __future__ import annotations

import json
import sys
import threading
import webbrowser
from datetime import datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, send_file

from analysis import summarize
from requests_client import run_requests
from selenium_client import run_selenium
from server import TLSCaptureServer


SOURCE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
# A frozen app's temporary extraction folder is read-only/ephemeral; keep data beside its executable instead.
RUNTIME_DIR = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else SOURCE_DIR
RESULTS_DIR = RUNTIME_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

app = Flask(__name__, template_folder=str(SOURCE_DIR / "templates"), static_folder=str(SOURCE_DIR / "static"))
state = {"running": False, "logs": [], "last_result_file": None}
state_lock = threading.Lock()


def log(message: str) -> None:
    entry = f"{datetime.now().strftime('%H:%M:%S')}  {message}"
    with state_lock:
        state["logs"].append(entry)


capture_server = TLSCaptureServer(log=log, data_dir=RUNTIME_DIR)


def build_payload() -> dict:
    records = capture_server.snapshot()
    with state_lock:
        logs = list(state["logs"])
        running = state["running"]
    return {"running": running, "logs": logs, "summary": summarize(records), "raw_records": records}


def experiment_worker() -> None:
    try:
        capture_server.clear()
        log("Experiment started: five fresh Selenium Chrome connections, then five fresh requests connections.")
        run_selenium(capture_server.url, 5, log)
        run_requests(capture_server.url, 5, log)
        # Wait briefly for the final server thread to associate the request label with its capture.
        capture_server.wait_for_label("requests", 5, timeout=5)
        # Mark execution complete before serializing so downloaded JSON never reports a stale running state.
        with state_lock:
            state["running"] = False
        log("Experiment measurements completed; serializing captured results.")
        payload = build_payload()
        output_path = RESULTS_DIR / f"tls-results-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        with state_lock:
            state["last_result_file"] = output_path
        log(f"Experiment finished. JSON saved: {output_path.name}")
    except Exception as error:  # keep dashboard responsive and surface orchestration failures
        log(f"Experiment orchestration failed: {error}")
    finally:
        with state_lock:
            state["running"] = False


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/results")
def results():
    return jsonify(build_payload())


@app.post("/api/run")
def run_experiment():
    with state_lock:
        if state["running"]:
            return jsonify({"ok": False, "message": "Experiment is already running."}), 409
        state["running"] = True
        state["logs"] = []
        state["last_result_file"] = None
    threading.Thread(target=experiment_worker, daemon=True, name="experiment-runner").start()
    return jsonify({"ok": True})


@app.get("/api/download")
def download():
    with state_lock:
        output_path = state["last_result_file"]
    if not output_path or not output_path.exists():
        return jsonify({"ok": False, "message": "No completed experiment JSON is available yet."}), 404
    return send_file(output_path, as_attachment=True, download_name=output_path.name, mimetype="application/json")


if __name__ == "__main__":
    capture_server.start()
    try:
        # Opening the local dashboard makes the packaged app usable without a command prompt step.
        threading.Timer(0.8, lambda: webbrowser.open("http://127.0.0.1:5000")).start()
        app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
    finally:
        capture_server.stop()

