# Local TLS ClientHello Fingerprinting Demo

This independent localhost project captures the actual TLS ClientHello bytes received by an HTTPS server. It compares five fresh Selenium Chrome connections with five fresh Python `requests` connections. It does **not** use HTTP User-Agent values as TLS fingerprints.

## What it records

- ClientHello legacy version, cipher suites, extension order, supported groups, and EC point formats
- Standard JA3 string and JA3 MD5 (with GREASE values removed)
- A companion comparison hash with only the extension sequence normalized (sorted)
- Per-client repeat consistency and a field-level Selenium-versus-requests comparison

The dashboard reports **구별 불가** when the selected JA3 hashes are equal. Equal fingerprints are a valid result, not an error, and no result claims that TLS alone proves browser automation.

## Windows setup

1. Install Python 3.10+ and Google Chrome.
2. Open PowerShell in this folder, then create and activate a virtual environment:

   ```powershell
   py -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```

3. Run `run.bat` by double-clicking it, or run the dashboard manually:

   ```powershell
   python app.py
   ```

4. Open `http://127.0.0.1:5000`, then choose **실험 시작**.

Selenium Manager normally obtains a compatible ChromeDriver automatically. If it cannot, install a ChromeDriver matching the installed Chrome version and place it on `PATH`; the dashboard log shows WebDriver failures.

## Local TLS behavior and connection isolation

- The TLS listener runs at `https://localhost:8443` and creates `certs/localhost-cert.pem` and `certs/localhost-key.pem` on first launch. These are local self-signed test files and should not be used elsewhere.
- The requests client uses a separate short-lived `Session` for every run, disables environment proxies (`trust_env=False`), and sends `Connection: close`. The server also returns `Connection: close`.
- Selenium starts and exits a separate Chrome process for every probe. This ensures a new connection attempt for each of the five runs.
- The dashboard only includes records whose post-handshake localhost probe URL supplied the expected `client` and `run` label. Other browser/background connections remain unlabelled and are not compared.
- Run this on localhost with no proxy. If a corporate proxy, VPN, security product, or TLS interception is active, the captured ClientHello may represent that intermediary rather than the intended client. The peer is recorded in each raw result; verify it is `127.0.0.1` and check the experiment logs.

## Result files

After an experiment finishes, the exact dashboard payload is written to `results/tls-results-YYYYMMDD-HHMMSS.json` and can be downloaded with the dashboard button.

## EXE distribution

Run `build-exe.bat` on a prepared development machine. It creates `dist/TLSFingerprintDemo.exe`; distribute that file together with `README-distribution.txt`. The EXE bundles Python and the required Python libraries, but Google Chrome remains a prerequisite for the Selenium portion of the experiment.

