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

# KOTLIN KODUNDAN PORT EDİLEN YENİ SINIF
class ContentX(ExtractorApi):
    name = "ContentX"
    requires_referer = True

    async def get_url(self, url, referer=None, subtitle_callback=None, callback=None, context=None):
        headers = HEADERS.copy()
        headers["Referer"] = referer if referer else url
        
        # Bu extractor kendi Playwright oturumunu yönetir
        async with async_playwright() as p:
            browser = None
            try:
                # Proxy ile veya proxysiz başlatma mantığı
                try:
                    browser = await p.firefox.launch(headless=True, proxy=PROXY)
                    pw_context = await browser.new_context(user_agent=HEADERS["User-Agent"])
                    await stealth_async(pw_context)
                    page = await pw_context.new_page()
                    await page.goto(url, timeout=90000, wait_until="load")
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    if browser: await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    pw_context = await browser.new_context(user_agent=HEADERS["User-Agent"])
                    await stealth_async(pw_context)
                    page = await pw_context.new_page()
                    await page.goto(url, timeout=90000, wait_until="load")

                i_source = await page.content()
                base_iframe_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

                # 1. Altyazıları Çıkar (Kotlin kodundaki gibi)
                sub_urls = set()
                # Regex düzeltildi, escape karakterlerini ve unicode'u daha iyi işler
                for match in re.finditer(r'"file":"((?:\\"|[^"])*)","label":"((?:\\"|[^"])*)"', i_source):
                    sub_url = match.group(1).replace("\\/", "/").replace('\\"', '"')
                    if ".vtt" not in sub_url: continue # Sadece altyazıları al
                    
                    sub_lang = match.group(2).replace("\\u0131", "ı").replace("\\u0130", "İ").replace("\\u00fc", "ü").replace("\\u00e7", "ç").replace("\\u011f", "ğ").replace("\\u015f", "ş")
                    
                    if sub_url not in sub_urls:
                        sub_urls.add(sub_url)
                        logger.info(f"Altyazı bulundu: Dil: {sub_lang}, URL: {sub_url}")
                        if subtitle_callback:
                            await subtitle_callback({"dil": sub_lang, "url": urljoin(base_iframe_url, sub_url)})
                
                # 2. Ana video linkini çıkar (Kotlin: 2 adımlı yöntem)
                open_player_match = re.search(r"window\.openPlayer\('([^']+)'\)", i_source)
                if not open_player_match:
                    raise Exception("ContentX Hatası: `window.openPlayer` kalıbı bulunamadı. Site yapısı değişmiş.")

                i_extract_val = open_player_match.group(1)
                source_url = f"{base_iframe_url}/source2.php?v={i_extract_val}"
                logger.info(f"ContentX: source2.php adresine gidiliyor -> {source_url}")

                await page.goto(source_url, timeout=90000, wait_until="load")
                vid_source = await page.content()

                vid_extract_match = re.search(r'"file":"([^"]+)"', vid_source)
                if not vid_extract_match:
                    raise Exception("ContentX Hatası: `source2.php` içinde video linki bulunamadı.")
                
                m3u_link = vid_extract_match.group(1).replace("\\", "")
                logger.info(f"Video linki başarıyla bulundu: {m3u_link}")
                if callback:
                    await callback({"kaynak": "ContentX", "isim": "ContentX Video", "url": m3u_link, "tur": "m3u8"})
                
                # 3. Dublajlı versiyonu kontrol et (Kotlin kodundaki gibi)
                dublaj_match = re.search(r""","([^']+)","Türkçe""", i_source)
                if dublaj_match:
                    dublaj_extract_val = dublaj_match.group(1)
                    dublaj_source_url = f"{base_iframe_url}/source2.php?v={dublaj_extract_val}"
                    logger.info(f"ContentX: Türkçe dublaj için source2.php adresine gidiliyor -> {dublaj_source_url}")

                    await page.goto(dublaj_source_url, timeout=90000, wait_until="load")
                    dublaj_vid_source = await page.content()
                    
                    dublaj_vid_match = re.search(r'"file":"([^"]+)"', dublaj_vid_source)
                    if dublaj_vid_match:
                        dublaj_m3u_link = dublaj_vid_match.group(1).replace("\\", "")
                        logger.info(f"Türkçe dublaj linki bulundu: {dublaj_m3u_link}")
                        if callback:
                            await callback({"kaynak": "ContentX (Dublaj)", "isim": "ContentX Video (Dublaj)", "url": dublaj_m3u_link, "tur": "m3u8"})

                await browser.close()
                return # Başarıyla tamamlandı

            except Exception as e:
                logger.error(f"ContentX extractor içinde hata: {e}")
                if browser:
                    await browser.close()
                return

# DiziPalOrijinal sınıfı (Değişiklik yok)
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
        try:
            page_content = ""
            async with async_playwright() as p:
                browser = await p.firefox.launch(headless=True, proxy=PROXY)
                context = await browser.new_context(user_agent=HEADERS["User-Agent"])
                await stealth_async(context)
                for name, value in self.session_cookies.items():
                    await context.add_cookies([{"name": name, "value": value, "url": self.main_url}])
                page = await context.new_page()
                await page.goto(data, timeout=90000, wait_until="load")
                page_content = await page.content()
                await browser.close()
            
            soup = BeautifulSoup(page_content, 'html.parser')
            hidden_json_tag = soup.select_one("div[data-rm-k]")
            if not hidden_json_tag:
                logger.error("Şifreli JSON verisi 'div[data-rm-k]' içinde bulunamadı.")
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
                await extractor.get_url(iframe_url, referer=data, subtitle_callback=subtitle_callback, callback=callback)
            
            return True

        except Exception as e:
            logger.error(f"Link çıkarma hatası: {e}")
            return False

    async def calistir(self):
        await self.init_session()
        url = f"{self.main_url}/yabanci-dizi-izle"
        page_content = ""
        async with async_playwright() as p:
            browser = await p.firefox.launch(headless=True, proxy=PROXY)
            context = await browser.new_context(user_agent=HEADERS["User-Agent"])
            await stealth_async(context)
            for name, value in self.session_cookies.items():
                await context.add_cookies([{"name": name, "value": value, "url": self.main_url}])
            page = await context.new_page()
            await page.goto(url, timeout=90000, wait_until="load")
            page_content = await page.content()
            await browser.close()

        soup = BeautifulSoup(page_content, 'html.parser')
        series_divs = soup.select("div.prm-borderb")
        logger.info(f"Ana sayfada bulunan öğe sayısı: {len(series_divs)}")
        all_data = []
        
        for item in series_divs:
            try:
                a_tag = item.select_one("a")
                if not a_tag: continue
                
                raw_href = a_tag.get("href", "")
                series_href = ""
                if "/bolum/" in raw_href:
                    # Bölüm linkinden ana dizi linkini türetme
                    parts = raw_href.split('/')[2].split('-')
                    if 'sezon' in parts and 'bolum' in parts:
                        sezon_index = parts.index('sezon')
                        series_name = '-'.join(parts[:sezon_index-1])
                        series_href = f"/series/{series_name}"
                    else: # Daha genel bir fallback
                        series_href = "/series/" + '-'.join(raw_href.split('/')[2].split('-')[:-4])
                elif "/series/" in raw_href:
                    series_href = raw_href
                else: continue

                series_url = urljoin(self.main_url, series_href)
                title = item.select_one("img").get("alt", "Bilinmeyen Başlık")
                logger.info(f"İşleniyor: {title} ({series_url})")

                # Dizinin kendi sayfasına gitmeye gerek kalmadan bölüm linklerini alabiliriz.
                # Şimdilik örnek olarak ilk bölümü işleyelim.
                # Gerçek bir uygulamada tüm bölümleri gezmek için bir yapı kurulmalı.
                
                # Sadece bir bölümü test etmek için örnek bölüm URL'si alınıyor
                first_episode_url = urljoin(self.main_url, raw_href)
                
                logger.info(f"Bölüm işleniyor: {first_episode_url}")
                video_data = {"linkler": [], "altyazilar": []}

                async def subtitle_callback(subtitle):
                    logger.info(f"Altyazı eklendi: {subtitle}")
                    video_data["altyazilar"].append(subtitle)
                async def callback(link):
                    logger.info(f"Link eklendi: {link}")
                    video_data["linkler"].append(link)

                await self.load_links(first_episode_url, False, subtitle_callback, callback)
                all_data.append({"baslik": title, "url": series_url, "bolum_bilgisi": video_data})

            except Exception as e:
                logger.error(f"Bir seri işlenirken hata oluştu: {e}")
                continue

        with open("dizipal_sonuclar.json", "w", encoding="utf-8") as f:
            json.dump(all_data, f, ensure_ascii=False, indent=4)
        logger.info("Tüm veriler 'dizipal_sonuclar.json' dosyasına kaydedildi.")

# Ana çalıştırma
if __name__ == "__main__":
    dizipal = DiziPalOrijinal()
    asyncio.run(dizipal.calistir())
