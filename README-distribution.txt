TLS Fingerprinting Demo - distribution notes
============================================

1. Install Google Chrome on the target PC.
2. Double-click TLSFingerprintDemo.exe.
3. The local dashboard should open at http://127.0.0.1:5000.
4. Press "실험 시작" and wait for both 5-run tests to complete.

No Python installation is needed for the EXE itself.

The program creates these folders beside the EXE:
- certs: a localhost-only self-signed certificate and private key
- results: JSON files from completed experiments

Keep the EXE in a writable folder such as Desktop or Documents. Do not run it
from a network share or a protected system folder. Google Chrome is still
required because Selenium drives the installed local Chrome browser.

Windows SmartScreen may warn about an unsigned EXE. This is expected for a
locally built executable. For public distribution, sign the EXE with an
Authenticode code-signing certificate.

