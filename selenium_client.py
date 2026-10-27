"""Fresh Chrome process per run so each probe creates a new TLS connection."""

from __future__ import annotations

from selenium import webdriver
from selenium.common.exceptions import WebDriverException


def run_selenium(base_url: str, runs: int, log) -> None:
    for run in range(1, runs + 1):
        driver = None
        try:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless=new")
            options.add_argument("--ignore-certificate-errors")  # only localhost self-signed certificate
            options.add_argument("--disable-background-networking")
            options.add_argument("--no-proxy-server")
            options.add_argument("--no-first-run")
            options.add_argument("--no-default-browser-check")
            options.add_argument("--disable-gpu")
            driver = webdriver.Chrome(options=options)
            driver.get(f"{base_url}/probe?client=selenium&run={run}")
            if "ok" not in driver.page_source:
                raise RuntimeError("server did not return expected probe body")
            log(f"Selenium Chrome run {run}/{runs}: page loaded")
        except (WebDriverException, RuntimeError) as error:
            log(f"Selenium Chrome run {run}/{runs} failed: {error}")
        finally:
            if driver:
                driver.quit()

