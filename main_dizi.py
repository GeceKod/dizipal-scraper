from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import json
import logging
import os
import re
import time

from bs4 import BeautifulSoup
import tmdbsimple as tmdb

from dizipal_common import (
    DEFAULT_USER_AGENT,
    FetchPayload,
    atomic_write_json,
    bootstrap_session,
    cache_entry_is_fresh,
    clean_space,
    configure_logging,
    detect_total_pages,
    extract_first_youtube_url,
    extract_heading_text,
    extract_labeled_value,
    extract_meta_content,
    fetch_html,
    iso_now,
    is_within_ttl,
    load_json_list,
    normalize_site_url,
    save_state,
    unique_preserve_order,
)


DEFAULT_DESCRIPTION = "Aciklama yok."
DEFAULT_PLATFORM = "Platform Disi"
LIST_TITLE_NOISE = {"dublaj", "altyazi", "altyazili", "turkce", "izle", "hd"}
TMDB_TITLE_CLEAN_RE = re.compile(r"\b(izle|full|hd|turkce dublaj|altyazili|dublaj|sezon|bolum)\b", re.I)
EPISODE_PATTERNS = (
    re.compile(r"-(\d+)-sezon-(\d+)-bolum", re.I),
    re.compile(r"-(\d+)x(\d+)(?:$|[/?#-])", re.I),
)
logger = logging.getLogger("dizi_sync")


@dataclass(frozen=True)
class AppConfig:
    base_domain: str
    list_url: str
    data_file: Path
    legacy_data_file: Path
    state_file: Path
    log_file: Path
    backup_file: Path
    http_timeout: int
    http_retries: int
    http_retry_sleep: float
    selenium_wait_seconds: int
    selenium_headless: bool
    max_list_pages: int
    list_probe_limit: int
    session_ttl: timedelta
    checkpoint_item_interval: int
    tmdb_hit_ttl: timedelta
    tmdb_miss_ttl: timedelta
    tmdb_error_ttl: timedelta
    browser_impersonation: str
    tmdb_api_key: str
    proxy: str


@dataclass(frozen=True)
class SeriesListItem:
    url: str
    title: str
    poster: str


def load_config() -> AppConfig:
    base_domain = os.getenv("DIZI_BASE_DOMAIN", "https://dizipal1542.com").rstrip("/")
    list_url = normalize_site_url(os.getenv("DIZI_LIST_URL", "/yabanci-dizi-izle"), base_domain)
    data_file = Path(os.getenv("DIZI_DATA_FILE", "diziler.json"))
    return AppConfig(
        base_domain=base_domain,
        list_url=list_url,
        data_file=data_file,
        legacy_data_file=Path(os.getenv("DIZI_LEGACY_DATA_FILE", "diziler_full.json")),
        state_file=Path(os.getenv("DIZI_STATE_FILE", "diziler_state.json")),
        log_file=Path(os.getenv("DIZI_LOG_FILE", "logs/dizi_sync.log")),
        backup_file=Path(f"{data_file}.bak"),
        http_timeout=int(os.getenv("DIZI_HTTP_TIMEOUT", "20")),
        http_retries=int(os.getenv("DIZI_HTTP_RETRIES", "3")),
        http_retry_sleep=float(os.getenv("DIZI_HTTP_RETRY_SLEEP", "1.5")),
        selenium_wait_seconds=int(os.getenv("DIZI_SELENIUM_WAIT", "18")),
        selenium_headless=os.getenv("DIZI_SELENIUM_HEADLESS", "0") == "1",
        max_list_pages=max(0, int(os.getenv("DIZI_MAX_LIST_PAGES", "0"))),
        list_probe_limit=max(2, int(os.getenv("DIZI_LIST_PROBE_LIMIT", "250"))),
        session_ttl=timedelta(hours=int(os.getenv("DIZI_SESSION_TTL_HOURS", "12"))),
        checkpoint_item_interval=max(1, int(os.getenv("DIZI_CHECKPOINT_ITEMS", "10"))),
        tmdb_hit_ttl=timedelta(days=int(os.getenv("DIZI_TMDB_HIT_TTL_DAYS", "30"))),
        tmdb_miss_ttl=timedelta(days=int(os.getenv("DIZI_TMDB_MISS_TTL_DAYS", "7"))),
        tmdb_error_ttl=timedelta(hours=int(os.getenv("DIZI_TMDB_ERROR_TTL_HOURS", "6"))),
        browser_impersonation=os.getenv("DIZI_IMPERSONATE", "chrome131"),
        tmdb_api_key=os.getenv("TMDB_API_KEY", "48ce82f1de91232f542660e99a9d1336"),
        proxy=os.getenv("DIZI_PROXY") or os.getenv("SCRAPER_PROXY", ""),
    )


def default_state() -> dict[str, Any]:
    return {"version": 2, "session": {}, "series": {}, "tmdb_cache": {}, "run": {}}


def load_state(path: Path) -> dict[str, Any]:
    if not path.exists():
        return default_state()
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (json.JSONDecodeError, OSError):
        return default_state()
    if not isinstance(raw, dict):
        return default_state()
    state = default_state()
    for key in state:
        if isinstance(raw.get(key), dict):
            state[key] = raw[key]
    if isinstance(raw.get("version"), int):
        state["version"] = raw["version"]
    return state


def load_series_database(config: AppConfig) -> list[dict[str, Any]]:
    if not config.data_file.exists() and config.legacy_data_file.exists():
        atomic_write_json(config.data_file, load_json_list(config.legacy_data_file))
    if not config.data_file.exists():
        return []
    try:
        return load_json_list(config.data_file)
    except Exception:
        if config.backup_file.exists():
            payload = load_json_list(config.backup_file)
            atomic_write_json(config.data_file, payload)
            return payload
        raise


def slug_to_title(url: str) -> str:
    slug = urlparse(url).path.rstrip("/").split("/")[-1]
    slug = re.sub(r"-(\d+)x(\d+)$", "", slug, flags=re.I)
    return clean_space(slug.replace("-", " "))


def clean_list_title(raw_text: str, url: str) -> str:
    text = clean_space(raw_text)
    if not text:
        return slug_to_title(url)
    tokens = text.split()
    while tokens and tokens[0].casefold() in LIST_TITLE_NOISE:
        tokens.pop(0)
    if tokens and re.fullmatch(r"(19|20)\d{2}", tokens[0]):
        tokens.pop(0)
    if tokens and re.fullmatch(r"\d+(?:\.\d+)?", tokens[0]):
        tokens.pop(0)
    return clean_space(" ".join(tokens)) or slug_to_title(url)


def extract_anchor_image(anchor: Any, base_domain: str) -> str:
    for scope in (anchor, anchor.parent):
        if not getattr(scope, "find", None):
            continue
        image = scope.find("img")
        if image:
            src = image.get("data-src") or image.get("data-lazy-src") or image.get("src")
            if src:
                return normalize_site_url(src, base_domain)
    return ""


def extract_anchor_title(anchor: Any, url: str) -> str:
    for candidate in (anchor.get("title"), anchor.get("aria-label"), anchor.get("data-title")):
        if clean_space(candidate):
            return clean_space(candidate)
    image = anchor.find("img")
    if image and clean_space(image.get("alt")):
        return clean_space(image.get("alt"))
    return clean_list_title(anchor.get_text(" ", strip=True), url)


def extract_series_list_items(soup: BeautifulSoup, base_domain: str) -> list[SeriesListItem]:
    items: list[SeriesListItem] = []
    seen: set[str] = set()
    for anchor in soup.find_all("a", href=True):
        url = normalize_site_url(anchor.get("href"), base_domain)
        if "/series/" not in urlparse(url).path.lower() or url in seen:
            continue
        seen.add(url)
        items.append(SeriesListItem(url, extract_anchor_title(anchor, url), extract_anchor_image(anchor, base_domain)))
    return items


def extract_series_items_from_html(html: str, base_domain: str) -> list[SeriesListItem]:
    return extract_series_list_items(BeautifulSoup(html, "html.parser"), base_domain) if html else []


def parse_episode_numbers(url: str) -> tuple[int, int]:
    lowered = url.lower()
    for pattern in EPISODE_PATTERNS:
        match = pattern.search(lowered)
        if match:
            return int(match.group(1)), int(match.group(2))
    return 0, 0


def build_episode_record(series_title: str, episode_url: str, existing: dict[str, Any] | None = None) -> dict[str, Any]:
    season_no, episode_no = parse_episode_numbers(episode_url)
    payload = dict(existing or {})
    payload["url"] = episode_url
    payload["videoUrl"] = episode_url
    payload["title"] = (
        f"{series_title} {season_no}. Sezon {episode_no}. Bolum" if season_no and episode_no else payload.get("title") or series_title
    )
    payload["episode_number"] = f"{episode_no}. Bolum" if episode_no else payload.get("episode_number") or "1. Bolum"
    payload["thumbnail"] = payload.get("thumbnail", "")
    return payload


def extract_series_detail_soup(soup: BeautifulSoup, series_url: str, base_domain: str) -> dict[str, Any]:
    episode_links = unique_preserve_order(
        normalize_site_url(anchor.get("href"), base_domain)
        for anchor in soup.find_all("a", href=True)
        if "/bolum/" in anchor.get("href", "")
    )
    image = normalize_site_url(extract_meta_content(soup, "og:image"), base_domain)
    return {
        "title": extract_heading_text(soup) or clean_space(re.sub(r"\s*izle.*$", "", extract_meta_content(soup, "og:title"), flags=re.I)) or slug_to_title(series_url),
        "description": extract_meta_content(soup, "description") or extract_meta_content(soup, "og:description"),
        "poster": image,
        "cover_image": image,
        "platform": extract_labeled_value(soup, ("kanal", "platform")) or DEFAULT_PLATFORM,
        "added_date": extract_labeled_value(soup, ("guncellenme tarihi", "son guncelleme")),
        "imdb": extract_labeled_value(soup, ("imdb puani",)),
        "year": extract_labeled_value(soup, ("gosterim yili", "yil")),
        "trailer": extract_first_youtube_url(soup),
        "episode_links": episode_links,
    }


def build_tmdb_series_payload(info: dict[str, Any]) -> dict[str, Any]:
    videos = info.get("videos", {}).get("results", [])
    credits = info.get("credits", {})
    cast = credits.get("cast", [])
    external_ids = info.get("external_ids", {})
    return {
        "description": info.get("overview") or DEFAULT_DESCRIPTION,
        "imdb": str(round(info.get("vote_average", 0.0), 1)) if info.get("vote_average") else "",
        "imdb_id": external_ids.get("imdb_id", ""),
        "year": str(info.get("first_air_date", ""))[:4],
        "genres": [genre["name"] for genre in info.get("genres", []) if genre.get("name")],
        "cast": [person["name"] for person in cast[:12] if person.get("name")],
        "poster": f"https://image.tmdb.org/t/p/w500{info.get('poster_path')}" if info.get("poster_path") else "",
        "cover_image": f"https://image.tmdb.org/t/p/original{info.get('backdrop_path')}" if info.get("backdrop_path") else "",
        "trailer": next(
            (
                f"https://www.youtube.com/watch?v={video['key']}"
                for video in videos
                if video.get("site") == "YouTube" and "trailer" in video.get("type", "").lower() and video.get("key")
            ),
            "",
        ),
    }


def get_tmdb_series_data(title: str, state: dict[str, Any], config: AppConfig) -> dict[str, Any] | None:
    cache_key = clean_space(re.sub(r"[^\w\s]", " ", TMDB_TITLE_CLEAN_RE.sub(" ", title.casefold())))
    cache = state.setdefault("tmdb_cache", {})
    cached = cache.get(cache_key)
    if isinstance(cached, dict) and cache_entry_is_fresh(cached, config):
        if cached.get("status") == "hit":
            return dict(cached.get("data", {}))
        if cached.get("status") == "miss":
            return {}
        return None
    search = tmdb.Search()
    queries = [title, clean_space(TMDB_TITLE_CLEAN_RE.sub(" ", title))]
    try:
        result: dict[str, Any] = {}
        for query in unique_preserve_order(queries):
            result = search.tv(query=query)
            if result.get("results"):
                break
        if not result.get("results"):
            cache[cache_key] = {"status": "miss", "cached_at": iso_now(), "data": {}}
            return {}
        info = tmdb.TV(result["results"][0]["id"]).info(language="tr", append_to_response="videos,credits,external_ids")
        payload = build_tmdb_series_payload(info)
        cache[cache_key] = {"status": "hit", "cached_at": iso_now(), "data": payload}
        return dict(payload)
    except Exception as exc:
        logger.warning("TMDB hatasi (%s): %s", title, exc)
        cache[cache_key] = {"status": "error", "cached_at": iso_now(), "message": str(exc)[:500]}
        return None


class SessionContext:
    def __init__(self, config: AppConfig, state: dict[str, Any]) -> None:
        self.config = config
        self.state = state
        self.cookies: dict[str, str] = {}
        self.user_agent = DEFAULT_USER_AGENT
        self.page1_html = ""

    def ensure(self) -> None:
        session = self.state.get("session", {})
        cookies = session.get("cookies") if isinstance(session, dict) else None
        user_agent = session.get("user_agent") if isinstance(session, dict) else None
        captured_at = session.get("captured_at") if isinstance(session, dict) else None
        if isinstance(cookies, dict) and cookies and isinstance(user_agent, str) and is_within_ttl(captured_at, self.config.session_ttl):
            payload = fetch_html(self.config.list_url, cookies, user_agent, self.config)
            if payload.status_code == 200 and payload.text and extract_series_items_from_html(payload.text, self.config.base_domain):
                self.cookies = cookies
                self.user_agent = user_agent
                self.page1_html = payload.text
                return
        self.refresh()

    def refresh(self) -> None:
        cookies, user_agent, html = bootstrap_session(
            self.config,
            self.config.list_url,
            lambda body: extract_series_items_from_html(body, self.config.base_domain),
            logger,
            "dizi listesi",
        )
        self.cookies = cookies
        self.user_agent = user_agent
        self.page1_html = html
        self.state["session"] = {"cookies": cookies, "user_agent": user_agent, "captured_at": iso_now()}
        save_state(self.config.state_file, self.state)


def fetch_with_reauth(url: str, session_ctx: SessionContext) -> FetchPayload:
    payload = fetch_html(url, session_ctx.cookies, session_ctx.user_agent, session_ctx.config)
    if payload.status_code in (403, 429, 503) or not payload.text:
        session_ctx.refresh()
        payload = fetch_html(url, session_ctx.cookies, session_ctx.user_agent, session_ctx.config)
    return payload


def build_page_candidates(list_url: str, page: int) -> list[str]:
    if page <= 1:
        return [list_url]
    base = list_url.rstrip("/")
    return [f"{base}/page/{page}/", f"{base}/page/{page}", f"{list_url}?page={page}", f"{list_url}?paged={page}", f"{list_url}?sf_paged={page}"]


def gather_all_series_items(session_ctx: SessionContext) -> list[SeriesListItem]:
    first_items = extract_series_items_from_html(session_ctx.page1_html, session_ctx.config.base_domain)
    if not first_items:
        session_ctx.refresh()
        first_items = extract_series_items_from_html(session_ctx.page1_html, session_ctx.config.base_domain)
    if not first_items:
        raise RuntimeError("Ilk dizi liste sayfasinda hic kayit bulunamadi.")

    soup = BeautifulSoup(session_ctx.page1_html, "html.parser")
    detected_total = detect_total_pages(soup)
    probe_limit = session_ctx.config.max_list_pages or max(detected_total, session_ctx.config.list_probe_limit)
    seen: dict[str, SeriesListItem] = {item.url: item for item in first_items}
    fingerprint_history = {tuple(item.url for item in first_items)}
    empty_streak = 0

    for page in range(2, probe_limit + 1):
        page_items: list[SeriesListItem] = []
        for candidate in build_page_candidates(session_ctx.config.list_url, page):
            payload = fetch_with_reauth(candidate, session_ctx)
            if payload.status_code == 404:
                continue
            page_items = extract_series_items_from_html(payload.text, session_ctx.config.base_domain)
            if page_items:
                break
        if not page_items:
            empty_streak += 1
            if empty_streak >= 2 and detected_total <= 1:
                break
            if detected_total > 1 and page >= detected_total:
                break
            continue
        fingerprint = tuple(item.url for item in page_items)
        if fingerprint in fingerprint_history:
            empty_streak += 1
            if empty_streak >= 2:
                break
            continue
        fingerprint_history.add(fingerprint)
        empty_streak = 0
        for item in page_items:
            seen.setdefault(item.url, item)
        if detected_total > 1 and page >= detected_total:
            break
    return list(seen.values())


def merge_series_record(existing: dict[str, Any] | None, item: SeriesListItem, site_payload: dict[str, Any], tmdb_payload: dict[str, Any] | None) -> dict[str, Any]:
    existing = dict(existing or {})
    current_links = site_payload.get("episode_links", [])
    existing_episodes = {episode.get("url"): episode for episode in existing.get("episodes", []) if episode.get("url")}
    episodes = [build_episode_record(site_payload.get("title") or item.title, link, existing_episodes.get(link)) for link in unique_preserve_order(current_links + list(existing_episodes))]
    merged = {
        "type": "dizi",
        "title": site_payload.get("title") or item.title,
        "url": item.url,
        "poster": site_payload.get("poster") or item.poster or existing.get("poster", ""),
        "cover_image": site_payload.get("cover_image") or existing.get("cover_image", ""),
        "platform": site_payload.get("platform") or existing.get("platform", DEFAULT_PLATFORM) or DEFAULT_PLATFORM,
        "added_date": site_payload.get("added_date") or existing.get("added_date", ""),
        "episodes": episodes,
        "description": site_payload.get("description") or existing.get("description", DEFAULT_DESCRIPTION) or DEFAULT_DESCRIPTION,
        "imdb": site_payload.get("imdb") or existing.get("imdb", "0.0") or "0.0",
        "imdb_id": existing.get("imdb_id", ""),
        "year": site_payload.get("year") or existing.get("year", ""),
        "genres": existing.get("genres", []),
        "cast": existing.get("cast", []),
        "trailer": site_payload.get("trailer") or existing.get("trailer", ""),
    }
    if tmdb_payload is not None:
        for field in ("description", "imdb", "imdb_id", "year", "genres", "cast", "poster", "cover_image", "trailer"):
            if tmdb_payload.get(field):
                merged[field] = tmdb_payload[field]
    if not merged["description"]:
        merged["description"] = DEFAULT_DESCRIPTION
    return merged


def main() -> None:
    config = load_config()
    configure_logging(logger, config.log_file)
    tmdb.API_KEY = config.tmdb_api_key
    state = load_state(config.state_file)
    session_ctx = SessionContext(config, state)
    session_ctx.ensure()

    all_series = load_series_database(config)
    url_map = {entry.get("url"): index for index, entry in enumerate(all_series) if entry.get("url")}
    items = gather_all_series_items(session_ctx)
    logger.info("%s benzersiz dizi bulundu.", len(items))

    changes = 0
    for index, item in enumerate(items, start=1):
        logger.info("[%s/%s] %s", index, len(items), item.title)
        payload = fetch_with_reauth(item.url, session_ctx)
        if payload.status_code != 200 or not payload.text:
            logger.error("Dizi sayfasi alinamadi: %s", item.url)
            continue
        site_payload = extract_series_detail_soup(BeautifulSoup(payload.text, "html.parser"), item.url, config.base_domain)
        if not site_payload.get("episode_links"):
            logger.error("Bolum listesi yok: %s", item.url)
            continue
        tmdb_payload = get_tmdb_series_data(site_payload.get("title") or item.title, state, config)
        merged = merge_series_record(all_series[url_map[item.url]] if item.url in url_map else None, item, site_payload, tmdb_payload)
        existing_index = url_map.get(item.url)
        if existing_index is None:
            all_series.append(merged)
            url_map[item.url] = len(all_series) - 1
            changes += 1
        elif all_series[existing_index] != merged:
            all_series[existing_index] = merged
            changes += 1
        state.setdefault("series", {})[item.url] = {
            "title": merged["title"],
            "episode_count": len(merged["episodes"]),
            "updated_at": iso_now(),
        }
        if changes and changes % config.checkpoint_item_interval == 0:
            atomic_write_json(config.data_file, all_series, backup_path=config.backup_file)
            save_state(config.state_file, state)

    atomic_write_json(config.data_file, all_series, backup_path=config.backup_file)
    state.setdefault("run", {}).update({"status": "success", "last_completed_at": iso_now()})
    save_state(config.state_file, state)
    logger.info("Dizi senkronizasyonu tamamlandi. Toplam kayit: %s", len(all_series))


if __name__ == "__main__":
    main()
