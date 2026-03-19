from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import local
from typing import Any, Callable, Iterable
from urllib.parse import urljoin, urlparse, urlunparse

import json
import os
import re
import shutil
import time

from bs4 import BeautifulSoup
from curl_cffi import requests
from seleniumbase import SB


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/131.0.0.0 Safari/537.36"
)
CHALLENGE_MARKERS = (
    "just a moment",
    "cf-chl",
    "cf-browser-verification",
    "/cdn-cgi/challenge-platform/",
    "challenges.cloudflare.com/turnstile",
    "verify you are human",
    "attention required",
    "enable javascript and cookies to continue",
    "cf-mitigated",
    "too many requests",
    "openresty",
    "access denied",
)
SITE_HOST_RE = re.compile(r"^dizipal\d+\.com$", flags=re.IGNORECASE)
TR_ASCII_MAP = str.maketrans(
    {
        "c": "c",
        "C": "C",
        "g": "g",
        "G": "G",
        "i": "i",
        "I": "I",
        "o": "o",
        "O": "O",
        "s": "s",
        "S": "S",
        "u": "u",
        "U": "U",
        "ç": "c",
        "Ç": "C",
        "ğ": "g",
        "Ğ": "G",
        "ı": "i",
        "İ": "I",
        "ö": "o",
        "Ö": "O",
        "ş": "s",
        "Ş": "S",
        "ü": "u",
        "Ü": "U",
    }
)
thread_local = local()


@dataclass
class FetchPayload:
    url: str
    status_code: int | None
    text: str = ""
    error: str = ""
    final_url: str = ""

    @property
    def challenge(self) -> bool:
        return is_cloudflare_challenge(self.text)

    def soup(self) -> BeautifulSoup | None:
        if not self.text:
            return None
        return BeautifulSoup(self.text, "html.parser")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def parse_iso_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def is_within_ttl(value: str | None, ttl: timedelta) -> bool:
    parsed = parse_iso_datetime(value)
    if parsed is None:
        return False
    return utc_now() - parsed <= ttl


def configure_logging(logger: Any, log_file: Path) -> None:
    import logging

    log_file.parent.mkdir(parents=True, exist_ok=True)
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)


def atomic_write_json(path: Path, payload: Any, backup_path: Path | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_suffix(path.suffix + ".tmp")
    try:
        with temp_path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
        with temp_path.open("r", encoding="utf-8") as handle:
            json.load(handle)
        if backup_path and path.exists():
            shutil.copy2(path, backup_path)
        os.replace(temp_path, path)
    finally:
        if temp_path.exists():
            temp_path.unlink(missing_ok=True)


def save_state(path: Path, state: dict[str, Any]) -> None:
    atomic_write_json(path, state)


def load_json_list(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    if not isinstance(payload, list):
        raise ValueError(f"{path} liste formatinda degil.")
    return payload


def clean_space(value: str | None) -> str:
    return re.sub(r"\s+", " ", (value or "").strip())


def ascii_fold(value: str | None) -> str:
    return clean_space(value).translate(TR_ASCII_MAP).casefold()


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            result.append(value)
    return result


def is_cloudflare_challenge(html: str) -> bool:
    lowered = html.lower()
    return any(marker in lowered for marker in CHALLENGE_MARKERS)


def get_http_session() -> requests.Session:
    session = getattr(thread_local, "session", None)
    if session is None:
        session = requests.Session()
        thread_local.session = session
    return session


def build_headers(user_agent: str | None, referer: str) -> dict[str, str]:
    return {
        "User-Agent": user_agent or DEFAULT_USER_AGENT,
        "Referer": referer,
        "Accept-Language": "tr-TR,tr;q=0.9,en;q=0.8",
    }


def normalize_http_proxy(proxy: str | None) -> str:
    proxy = clean_space(proxy)
    if not proxy:
        return ""
    if "://" in proxy:
        return proxy
    return f"http://{proxy}"


def normalize_browser_proxy(proxy: str | None) -> str:
    proxy = clean_space(proxy)
    if not proxy:
        return ""
    parsed = urlparse(proxy if "://" in proxy else f"http://{proxy}")
    host = parsed.hostname or ""
    port = f":{parsed.port}" if parsed.port else ""
    if not host:
        return proxy
    if parsed.username is not None:
        password = parsed.password or ""
        return f"{parsed.username}:{password}@{host}{port}"
    return f"{host}{port}"


def fetch_html(url: str, cookies: dict[str, str], user_agent: str, config: Any) -> FetchPayload:
    last_error = ""
    proxy = normalize_http_proxy(getattr(config, "proxy", ""))
    for attempt in range(1, config.http_retries + 1):
        try:
            response = get_http_session().get(
                url,
                cookies=cookies or None,
                headers=build_headers(user_agent, config.base_domain),
                impersonate=config.browser_impersonation,
                timeout=config.http_timeout,
                allow_redirects=True,
                proxy=proxy or None,
            )
            return FetchPayload(
                url=url,
                status_code=response.status_code,
                text=response.text or "",
                final_url=str(response.url),
            )
        except Exception as exc:
            last_error = str(exc)
            if attempt < config.http_retries:
                time.sleep(config.http_retry_sleep * attempt)
    return FetchPayload(url=url, status_code=None, error=last_error)


def canonicalize_site_host(url: str, base_domain: str) -> str:
    parsed = urlparse(url)
    base = urlparse(base_domain)
    if not SITE_HOST_RE.match(parsed.hostname or ""):
        return url
    return urlunparse(parsed._replace(scheme=base.scheme, netloc=base.netloc))


def normalize_site_url(url: str | None, base_domain: str) -> str:
    if not url:
        return ""
    normalized = urljoin(base_domain.rstrip("/") + "/", url.strip())
    return canonicalize_site_host(normalized, base_domain)


def extract_meta_content(soup: BeautifulSoup, key: str) -> str:
    for attrs in ({"property": key}, {"name": key}):
        node = soup.find("meta", attrs=attrs)
        if node and node.get("content"):
            return clean_space(node["content"])
    return ""


def extract_heading_text(soup: BeautifulSoup) -> str:
    for tag_name in ("h1", "h2"):
        tag = soup.find(tag_name)
        text = clean_space(tag.get_text(" ", strip=True) if tag else "")
        if text:
            return text
    return ""


def extract_first_youtube_url(soup: BeautifulSoup) -> str:
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "")
        if "youtube.com" in href or "youtu.be" in href:
            return href.strip()
    return ""


def extract_labeled_value(soup: BeautifulSoup, labels: Iterable[str], max_lookahead: int = 4) -> str:
    normalized_labels = {ascii_fold(label) for label in labels}
    lines = [clean_space(text) for text in soup.stripped_strings]
    lines = [line for line in lines if line]
    for index, line in enumerate(lines):
        if ascii_fold(line) not in normalized_labels:
            continue
        for candidate in lines[index + 1 : index + 1 + max_lookahead]:
            if ascii_fold(candidate) not in normalized_labels:
                return candidate
    return ""


def detect_total_pages(soup: BeautifulSoup) -> int:
    total_pages = 1
    for anchor in soup.find_all("a", href=True):
        href = anchor.get("href", "")
        for pattern in (
            r"/page/(\d+)/?",
            r"[?&]page=(\d+)",
            r"[?&]paged=(\d+)",
            r"[?&]sf_paged=(\d+)",
        ):
            match = re.search(pattern, href, flags=re.IGNORECASE)
            if match:
                total_pages = max(total_pages, int(match.group(1)))
    return total_pages


def build_page_candidates(list_url: str, page: int) -> list[str]:
    if page <= 1:
        return [list_url]
    return [
        f"{list_url.rstrip('/')}/page/{page}/",
        f"{list_url.rstrip('/')}/page/{page}",
        f"{list_url}?page={page}",
        f"{list_url}?paged={page}",
        f"{list_url}?sf_paged={page}",
    ]


def cache_entry_is_fresh(entry: dict[str, Any], config: Any) -> bool:
    status = entry.get("status")
    cached_at = entry.get("cached_at")
    if status == "hit":
        ttl = config.tmdb_hit_ttl
    elif status == "miss":
        ttl = config.tmdb_miss_ttl
    else:
        ttl = config.tmdb_error_ttl
    return is_within_ttl(cached_at, ttl)


def save_bootstrap_debug_artifacts(
    config: Any,
    log_context: str,
    page_html: str,
    metadata: dict[str, Any],
    screenshot_bytes: bytes | None = None,
) -> tuple[Path, Path, Path | None]:
    debug_dir = config.log_file.parent / "bootstrap_debug"
    debug_dir.mkdir(parents=True, exist_ok=True)
    stamp = utc_now().strftime("%Y%m%d_%H%M%S")

    safe_context = re.sub(r"[^a-z0-9_-]+", "_", log_context.casefold())
    html_path = debug_dir / f"{safe_context}_{stamp}.html"
    meta_path = debug_dir / f"{safe_context}_{stamp}.json"
    screenshot_path = debug_dir / f"{safe_context}_{stamp}.png" if screenshot_bytes else None

    html_path.write_text(page_html or "", encoding="utf-8")
    meta_path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")
    if screenshot_path and screenshot_bytes:
        screenshot_path.write_bytes(screenshot_bytes)

    return html_path, meta_path, screenshot_path


def open_browser_target(sb: Any, target_url: str, wait_seconds: int, headless: bool) -> None:
    reconnect_time = max(6, min(max(wait_seconds - 2, 6), 25))
    if hasattr(sb, "uc_open_with_reconnect"):
        try:
            sb.uc_open_with_reconnect(target_url, reconnect_time)
            return
        except Exception:
            pass
    sb.open(target_url)
    if not headless:
        try:
            sb.maximize_window()
        except Exception:
            try:
                sb.driver.maximize_window()
            except Exception:
                pass


def bootstrap_session(
    config: Any,
    target_url: str,
    item_extractor: Callable[[str], list[Any]],
    logger: Any,
    log_context: str,
) -> tuple[dict[str, str], str, str]:
    logger.info("SeleniumBase ile %s oturumu alinacak.", log_context)
    use_xvfb = os.name != "nt" and not config.selenium_headless
    browser_proxy = normalize_browser_proxy(getattr(config, "proxy", ""))
    with SB(
        uc=True,
        headless=config.selenium_headless,
        xvfb=use_xvfb,
        proxy=browser_proxy or None,
    ) as sb:
        open_browser_target(sb, target_url, config.selenium_wait_seconds, config.selenium_headless)
        deadline = time.time() + config.selenium_wait_seconds
        page_html = ""
        items: list[Any] = []
        captcha_attempted = False
        retried_open = False
        time.sleep(3)

        while time.time() < deadline:
            try:
                page_html = sb.driver.page_source or ""
            except Exception:
                page_html = ""

            items = item_extractor(page_html)
            if items and not is_cloudflare_challenge(page_html):
                break

            if (
                is_cloudflare_challenge(page_html)
                and not captcha_attempted
                and hasattr(sb, "uc_gui_click_captcha")
            ):
                try:
                    sb.uc_gui_click_captcha()
                    captcha_attempted = True
                    time.sleep(2)
                    continue
                except Exception as exc:
                    logger.warning("Captcha tiklama denemesi basarisiz: %s", exc)
                    captcha_attempted = True

            if not retried_open and time.time() + 4 < deadline:
                try:
                    open_browser_target(
                        sb,
                        target_url,
                        config.selenium_wait_seconds,
                        config.selenium_headless,
                    )
                    retried_open = True
                    time.sleep(2)
                    continue
                except Exception as exc:
                    logger.warning("Tarayici yeniden acilamadi: %s", exc)
                    retried_open = True

            time.sleep(2)

        cookies = {cookie["name"]: cookie["value"] for cookie in sb.get_cookies()}
        try:
            user_agent = sb.get_user_agent() or DEFAULT_USER_AGENT
        except Exception:
            user_agent = DEFAULT_USER_AGENT

        if items and not is_cloudflare_challenge(page_html):
            logger.info("Tarayici oturumu hazir. Ilk sayfa kayit sayisi: %s", len(items))
            return cookies, user_agent, page_html

        http_payload = fetch_html(target_url, cookies, user_agent, config)
        if (
            http_payload.status_code == 200
            and http_payload.text
            and not is_cloudflare_challenge(http_payload.text)
        ):
            http_items = item_extractor(http_payload.text)
            if http_items:
                logger.info("HTTP dogrulamasi ile oturum dogrulandi. Kayit sayisi: %s", len(http_items))
                return cookies, user_agent, http_payload.text

        screenshot_bytes = None
        try:
            screenshot_bytes = sb.driver.get_screenshot_as_png()
        except Exception:
            screenshot_bytes = None

        current_url = ""
        current_title = ""
        try:
            current_url = getattr(sb.driver, "current_url", "") or ""
        except Exception:
            current_url = ""
        try:
            current_title = getattr(sb.driver, "title", "") or ""
        except Exception:
            current_title = ""

        html_path, meta_path, screenshot_path = save_bootstrap_debug_artifacts(
            config,
            log_context,
            page_html or http_payload.text,
            {
                "target_url": target_url,
                "current_url": current_url,
                "title": current_title,
                "browser_item_count": len(items),
                "browser_challenge_detected": is_cloudflare_challenge(page_html),
                "browser_html_length": len(page_html or ""),
                "http_status_code": http_payload.status_code,
                "http_final_url": http_payload.final_url,
                "http_error": http_payload.error,
                "http_challenge_detected": is_cloudflare_challenge(http_payload.text),
                "http_html_length": len(http_payload.text or ""),
            },
            screenshot_bytes=screenshot_bytes,
        )
        screenshot_hint = f", screenshot: {screenshot_path}" if screenshot_path else ""
        raise RuntimeError(
            f"{log_context} icin Cloudflare oturumu alinamadi. "
            f"Son URL: {current_url or target_url}. "
            f"Debug HTML: {html_path}, meta: {meta_path}{screenshot_hint}"
        )
