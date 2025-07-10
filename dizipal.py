import asyncio
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
from playwright.async_api import async_playwright
from playwright_stealth import stealth_async
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import base64
import hmac
import hashlib
import logging

# Loglama ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Proxy ayarları
PROXY = {
    "server": "socks5://45.89.28.226:12915",
}

# Başlık ayarları
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
}

# Şifre çözme fonksiyonu
def decrypt(passphrase, salt_hex, iv_hex, ciphertext_base64):
    try:
        salt = bytes.fromhex(salt_hex)
        iv = bytes.fromhex(iv_hex)
        ciphertext = base64.b64decode(ciphertext_base64)
        key = PBKDF2(passphrase, salt, dkLen=32, count=999, hmac_hash_module=SHA512)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        padding_len = plaintext[-1]
        plaintext = plaintext[:-padding_len]
        return plaintext.decode('utf-8')
    except Exception as e:
        logger.error(f"Şifre çözme hatası: {e}")
        raise

# Base ExtractorApi sınıfı
class ExtractorApi:
    async def get_url(self, url, referer=None, subtitle_callback=None, callback=None):
        raise NotImplementedError

# ContentX Extractor sınıfı (GÜNCELLENDİ)
class ContentX(ExtractorApi):
    name = "ContentX"
    main_url = "https://contentx.me"
    requires_referer = True

    async def get_url(self, url, referer=None, subtitle_callback=None, callback=None, context=None):
        headers = HEADERS.copy()
        headers["Referer"] = referer if referer else url
        async with async_playwright() as p:
            browser = None
            try:
                logger.info(f"Iframe URL'sine erişiliyor: {url}")
                # Proxy ile deneme
                browser = await p.firefox.launch(headless=True, proxy=PROXY)
                context = context or await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                await stealth_async(context)
                page = await context.new_page()
                try:
                    await page.goto(url, timeout=90000)
                    await page.wait_for_load_state("load")
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    context = await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                    await stealth_async(context)
                    page = await context.new_page()
                    await page.goto(url, timeout=90000)
                    await page.wait_for_load_state("load")

                i_source = await page.content()

                video_param = parse_qs(urlparse(url).query).get('v', [None])[0]
                filename = f"iframe_debug_{video_param or 'unknown'}.html"
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(i_source)
                logger.info(f"Iframe içeriği '{filename}' dosyasına kaydedildi.")

                sub_urls = set()
                altyazilar = []
                # Kotlin dosyasındaki altyazı regex'ine benzer şekilde güncellendi
                for match in re.finditer(r'"file":"((?:\\\\\"|[^"])+)","label":"((?:\\\\\"|[^"])+)"', i_source):
                    sub_url_raw = match.group(1)
                    sub_lang_raw = match.group(2)

                    sub_url = sub_url_raw.replace("\\/", "/").replace("\\u0026", "&").replace("\\", "")
                    sub_lang = sub_lang_raw.replace("\\u0131", "ı").replace("\\u0130", "İ").replace("\\u00fc", "ü").replace("\\u00e7", "ç").replace("\\u011f", "ğ").replace("\\u015f", "ş")

                    if sub_url not in sub_urls:
                        sub_urls.add(sub_url)
                        altyazilar.append({"dil": sub_lang, "url": urljoin(self.main_url, sub_url)})
                        if subtitle_callback:
                            await subtitle_callback(altyazilar[-1])

                linkler = []

                # Kotlin dosyasındaki gibi window.openPlayer metodunu arama ve source2.php'ye istek atma
                open_player_match = re.search(r"window\.openPlayer\('([^']+)'\)", i_source)
                if open_player_match:
                    i_extract_val = open_player_match.group(1)
                    base_iframe_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    source_url = f"{base_iframe_url}/source2.php?v={i_extract_val}"
                    logger.info(f"ContentX: source2.php'ye istek gönderiliyor: {source_url}")

                    await page.goto(source_url, timeout=90000)
                    await page.wait_for_load_state("load")
                    vid_source = await page.content()

                    with open("source2_debug.html", "w", encoding="utf-8") as f:
                        f.write(vid_source)
                    logger.info("source2.php içeriği 'source2_debug.html' dosyasına kaydedildi.")

                    # GÜNCELLENMİŞ REGEX VE TEMİZLEME
                    vid_extract_match = re.search(r'"file":"([^"]+)"', vid_source) # Daha genel regex
                    if vid_extract_match:
                        m3u_link = vid_extract_match.group(1)
                        m3u_link = m3u_link.replace("\\", "") # Kotlin'deki gibi ters slashları temizle
                        linkler.append({"kaynak": "ContentX (Source2 Video)", "isim": "ContentX Video", "url": m3u_link, "tur": "m3u8"})
                        if callback: await callback(linkler[-1])
                    await browser.close()
                    return {"linkler": linkler, "altyazilar": altyazilar}

                logger.warning(f"ContentX Hatası: Video linki bulunamadı. Sayfa içeriği değişmiş olabilir: {url}")
                await browser.close()
                return {"linkler": [], "altyazilar": altyazilar}

            except Exception as e:
                logger.error(f"ContentX çıkarma başarısız: {e}")
                if browser:
                    await browser.close()
                return {"linkler": [], "altyazilar": []}

# DiziPalOrijinal sınıfı
class DiziPalOrijinal:
    main_url = "https://dizipal935.com"
    name = "DiziPalOrijinal"
    has_main_page = True
    lang = "tr"

    def __init__(self):
        self.session_cookies = None
        self.c_key = None
        self.c_value = None
        self.extractors = [ContentX()]
        HEADERS['Referer'] = self.main_url + "/"

    async def init_session(self):
        if self.session_cookies and self.c_key and self.c_value:
            return
        logger.info("Oturum başlatılıyor: çerezler, cKey ve cValue alınıyor")
        async with async_playwright() as p:
            browser = None
            try:
                browser = await p.firefox.launch(headless=True, proxy=PROXY)
                context = await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                await stealth_async(context)
                page = await context.new_page()
                try:
                    await page.goto(self.main_url, timeout=90000)
                    await page.wait_for_load_state("load")
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    context = await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                    await stealth_async(context)
                    page = await context.new_page()
                    await page.goto(self.main_url, timeout=90000)
                    await page.wait_for_load_state("load")

                self.session_cookies = {cookie["name"]: cookie["value"] for cookie in await context.cookies()}
                soup = BeautifulSoup(await page.content(), 'html.parser')
                self.c_key = soup.select_one("input[name=cKey]")['value'] if soup.select_one("input[name=cKey]") else None
                self.c_value = soup.select_one("input[name=cValue]")['value'] if soup.select_one("input[name=cValue]") else None
                logger.info(f"cKey: {self.c_key}, cValue: {self.c_value}")
                if not self.c_key or not self.c_value:
                    raise ValueError("cKey veya cValue alınamadı")
                await browser.close()
            except Exception as e:
                logger.error(f"Oturum başlatma başarısız: {e}")
                if browser:
                    await browser.close()
                raise

    async def load_links(self, data, is_casting, subtitle_callback, callback):
        async with async_playwright() as p:
            browser = None
            try:
                browser = await p.firefox.launch(headless=True, proxy=PROXY)
                context = await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                await stealth_async(context)
                for name, value in self.session_cookies.items():
                    await context.add_cookies([{"name": name, "value": value, "url": self.main_url}])
                page = await context.new_page()
                try:
                    logger.info(f"Link sayfasına erişiliyor: {data}")
                    await page.goto(data, timeout=90000)
                    await page.wait_for_load_state("load")
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    context = await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                    await stealth_async(context)
                    for name, value in self.session_cookies.items():
                        await context.add_cookies([{"name": name, "value": value, "url": self.main_url}])
                    page = await context.new_page()
                    await page.goto(data, timeout=90000)
                    await page.wait_for_load_state("load")

                soup = BeautifulSoup(await page.content(), 'html.parser')
                hidden_json_tag = soup.select_one("div[data-rm-k]")
                if not hidden_json_tag:
                    logger.error("Şifreli JSON verisi 'div[data-rm-k]' içinde bulunamadı.")
                    await browser.close()
                    return False
                
                hidden_json = hidden_json_tag.text
                obj = json.loads(hidden_json)
                
                ciphertext = obj['ciphertext']
                iv = obj['iv']
                salt = obj['salt']
                passphrase = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
                
                decrypted_content = decrypt(passphrase, salt, iv, ciphertext)
                iframe_url = urljoin(self.main_url, decrypted_content) if not decrypted_content.startswith("http") else decrypted_content
                logger.info(f"Çözülen iframe URL: {iframe_url}")
                
                for extractor in self.extractors:
                    result = await extractor.get_url(iframe_url, referer=data, subtitle_callback=subtitle_callback, callback=callback, context=context)
                    if result["linkler"] or result["altyazilar"]:
                        await browser.close()
                        return True
                await browser.close()
                return False

            except Exception as e:
                logger.error(f"Link çıkarma hatası: {e}")
                if browser:
                    await browser.close()
                return False

    async def calistir(self):
        await self.init_session()
        url = f"{self.main_url}/yabanci-dizi-izle"
        async with async_playwright() as p:
            browser = None
            try:
                browser = await p.firefox.launch(headless=True, proxy=PROXY)
                context = await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                await stealth_async(context)
                for name, value in self.session_cookies.items():
                    await context.add_cookies([{"name": name, "value": value, "url": self.main_url}])
                page = await context.new_page()
                try:
                    logger.info(f"Ana sayfaya erişiliyor: {url}")
                    await page.goto(url, timeout=90000)
                    await page.wait_for_load_state("load")
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    context = await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                    await stealth_async(context)
                    for name, value in self.session_cookies.items():
                        await context.add_cookies([{"name": name, "value": value, "url": self.main_url}])
                    page = await context.new_page()
                    await page.goto(url, timeout=90000)
                    await page.wait_for_load_state("load")

                soup = BeautifulSoup(await page.content(), 'html.parser')
                series_divs = soup.select("div.prm-borderb")
                logger.info(f"Ana sayfada bulunan öğe sayısı: {len(series_divs)}")
                all_data = []
                processed_series_urls = set()

                for item in series_divs:
                    try:
                        a_tag = item.select_one("a")
                        if not a_tag:
                            continue
                        raw_href = a_tag.get("href", "")
                        series_href = ""
                        if "/bolum/" in raw_href:
                            parts = raw_href.split('/')[2].split('-')
                            if 'sezon' in parts and 'bolum' in parts:
                                sezon_index = parts.index('sezon')
                                series_name = '-'.join(parts[:sezon_index-1])
                                series_href = f"/series/{series_name}"
                            else:
                                series_href = "/series/" + '-'.join(raw_href.split('/')[2].split('-')[:-4])
                        elif "/series/" in raw_href:
                            series_href = raw_href
                        else:
                            continue

                        series_url = urljoin(self.main_url, series_href)
                        if series_url in processed_series_urls:
                            continue
                        processed_series_urls.add(series_url)

                        title = item.select_one("img").get("alt", "Bilinmeyen Başlık")
                        logger.info(f"İşleniyor: {title} ({series_url})")

                        await page.goto(series_url, timeout=90000)
                        await page.wait_for_load_state("load")
                        series_soup = BeautifulSoup(await page.content(), 'html.parser')
                        episode_links = series_soup.select("a.text.block[data-dizipal-pageloader='true']")
                        logger.info(f"  > {len(episode_links)} bölüm bulundu.")

                        series_data = {"baslik": title, "url": series_url, "bolumler": []}
                        for ep_link in episode_links:
                            episode_url = urljoin(self.main_url, ep_link['href'])
                            video_data = {"linkler": [], "altyazilar": []}
                            async def subtitle_callback(subtitle):
                                video_data["altyazilar"].append(subtitle)
                            async def callback(link):
                                video_data["linkler"].append(link)
                            logger.info(f"Bölüm işleniyor: {episode_url}")
                            await self.load_links(episode_url, False, subtitle_callback, callback)
                            series_data["bolumler"].append({"url": episode_url, "video_bilgisi": video_data})

                        all_data.append(series_data)

                    except Exception as e:
                        logger.error(f"Bir seri işlenirken hata oluştu: {e}")
                        continue

                await browser.close()
                with open("dizipal_sonuclar.json", "w", encoding="utf-8") as f:
                    json.dump(all_data, f, ensure_ascii=False, indent=4)
                logger.info("Tüm veriler 'dizipal_sonuclar.json' dosyasına kaydedildi.")

            except Exception as e:
                logger.error(f"Ana sayfa kazıma hatası: {e}")
                if browser:
                    await browser.close()

# Ana çalıştırma
if __name__ == "__main__":
    dizipal = DiziPalOrijinal()
    asyncio.run(dizipal.calistir())
