"""Repeatable localhost requests client for the TLS experiment."""

from __future__ import annotations

import urllib3
import requests


def run_requests(base_url: str, runs: int, log) -> None:
    # The local test certificate is intentionally untrusted; suppress only this expected warning.
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    for run in range(1, runs + 1):
        url = f"{base_url}/probe?client=requests&run={run}"
        try:
            # A new Session on every run disables environment proxies and cannot reuse an earlier connection.
            with requests.Session() as session:
                session.trust_env = False
                response = session.get(url, verify=False, headers={"Connection": "close"}, timeout=10)
                response.raise_for_status()
            log(f"requests run {run}/{runs}: HTTP {response.status_code}")
        except requests.RequestException as error:
            log(f"requests run {run}/{runs} failed: {error}")

