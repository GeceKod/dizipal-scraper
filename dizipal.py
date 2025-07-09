import asyncio
import requests
import time
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
        logger.info("Şifre çözme işlemi başlatılıyor")
        salt = bytes.fromhex(salt_hex)
        iv = bytes.fromhex(iv_hex)
        ciphertext = base64.b64decode(ciphertext_base64)
        logger.info("Salt, IV ve ciphertext başarıyla işlendi")
        key = PBKDF2(passphrase, salt, dkLen=32, count=999, hmac_hash_module=SHA512)
        logger.info("Anahtar başarıyla türetildi")
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        padding_len = plaintext[-1]
        plaintext = plaintext[:-padding_len]
        result = plaintext.decode('utf-8')
        logger.info("Şifre çözme başarılı")
        return result
    except Exception as e:
        logger.error(f"Şifre çözme hatası: {str(e)}")
        raise

# Base ExtractorApi sınıfı
class ExtractorApi:
    async def get_url(self, url, referer=None, subtitle_callback=None, callback=None):
        raise NotImplementedError

# Geliştirilmiş ContentX Extractor sınıfı
class ContentX(ExtractorApi):
    name = "ContentX"
    main_url = "https://contentx.me"
    requires_referer = True

    def __init__(self):
        self.m3u8_found = False

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
                
                # Network trafiğini izlemek için olay dinleyicisi
                def handle_response(response):
                    if any(ext in response.url for ext in [".m3u8", ".mp4", ".ts"]):
                        logger.info(f"Network trafiğinden video bulundu: {response.url}")
                        link = {
                            "kaynak": "Network Traffic",
                            "isim": "Video Akışı",
                            "url": response.url,
                            "tur": "m3u8"
                        }
                        asyncio.create_task(callback(link))
                        self.m3u8_found = True
                
                page.on("response", handle_response)
                
                try:
                    await page.goto(url, timeout=120000)
                    await page.wait_for_load_state("networkidle", timeout=60000)
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    context = await browser.new_context(user_agent=HEADERS["User-Agent"], bypass_csp=True)
                    await stealth_async(context)
                    page = await context.new_page()
                    page.on("response", handle_response)
                    await page.goto(url, timeout=120000)
                    await page.wait_for_load_state("networkidle", timeout=60000)

                i_source = await page.content()

                # Hata ayıklama için içerik kaydet
                domain = urlparse(url).netloc.replace(".", "_")
                filename = f"iframe_debug_{domain}.html"
                try:
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(i_source)
                    logger.info(f"Iframe içeriği '{filename}' dosyasına kaydedildi.")
                except Exception as e:
                    logger.error(f"Iframe içeriği kaydedilemedi: {e}")

                # Altyazıları çıkar
                sub_urls = set()
                altyazilar = []
                for match in re.finditer(r'"file":"([^"]+\.vtt[^"]*)","label":"([^"]+)"', i_source):
                    sub_url = match.group(1).replace("\\", "")
                    sub_lang = match.group(2).replace("\\u0131", "ı").replace("\\u0130", "İ").replace("\\u00fc", "ü").replace("\\u00e7", "ç")
                    if sub_url not in sub_urls:
                        sub_urls.add(sub_url)
                        altyazilar.append({"dil": sub_lang, "url": urljoin(self.main_url, sub_url)})
                        if subtitle_callback:
                            await subtitle_callback(altyazilar[-1])

                linkler = []
                
                # Yöntem 1: Direkt video elementinden src al
                try:
                    video_element = await page.query_selector("video")
                    if video_element:
                        video_src = await video_element.get_attribute("src")
                        if video_src and any(ext in video_src for ext in [".m3u8", ".mp4"]):
                            logger.info(f"Video elementinden link bulundu: {video_src}")
                            linkler.append({
                                "kaynak": "Direct Video Element",
                                "isim": "Video Akışı",
                                "url": video_src,
                                "tur": "m3u8"
                            })
                            if callback:
                                await callback(linkler[-1])
                except Exception as e:
                    logger.error(f"Video element kontrolü sırasında hata: {e}")

                # Yöntem 2: window.openPlayer ile source2.php'den link alma
                open_player_match = re.search(r"window\.openPlayer\('([^']+)'\)", i_source)
                if open_player_match and not self.m3u8_found and not linkler:
                    i_extract_val = open_player_match.group(1)
                    base_iframe_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    source_url = f"{base_iframe_url}/source2.php?v={i_extract_val}"
                    logger.info(f"ContentX: source2.php'ye istek gönderiliyor: {source_url}")

                    try:
                        await page.goto(source_url, timeout=90000)
                        await page.wait_for_load_state("networkidle")
                        vid_source = await page.content()

                        try:
                            with open("source2_debug.html", "w", encoding="utf-8") as f:
                                f.write(vid_source)
                            logger.info("source2.php içeriği 'source2_debug.html' dosyasına kaydedildi.")
                        except Exception as e:
                            logger.error(f"source2.php içeriği kaydedilemedi: {e}")

                        vid_extract_match = re.search(r'"file":"([^"]+)"', vid_source)
                        if vid_extract_match:
                            m3u_link = vid_extract_match.group(1).replace("\\", "")
                            logger.info(f"ContentX: source2.php içinden video linki bulundu: {m3u_link}")
                            linkler.append({
                                "kaynak": "ContentX (Source2 Video)", 
                                "isim": "ContentX Video", 
                                "url": m3u_link, 
                                "tur": "m3u8"
                            })
                            if callback:
                                await callback(linkler[-1])
                        else:
                            logger.warning("ContentX: source2.php içinde video linki bulunamadı.")
                    except Exception as e:
                        logger.error(f"ContentX: source2.php isteği başarısız: {e}")

                # Yöntem 3: Türkçe dublaj kontrolü
                dublaj_match = re.search(r',"([^"]+)","Türkçe"', i_source)
                if dublaj_match and not self.m3u8_found and not linkler:
                    dublaj_val = dublaj_match.group(1)
                    base_iframe_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    dublaj_source_url = f"{base_iframe_url}/source2.php?v={dublaj_val}"
                    logger.info(f"ContentX: Türkçe dublaj için source2.php'ye istek gönderiliyor: {dublaj_source_url}")
                    
                    try:
                        await page.goto(dublaj_source_url, timeout=90000)
                        await page.wait_for_load_state("networkidle")
                        dublaj_source = await page.content()

                        try:
                            with open("dublaj_source2_debug.html", "w", encoding="utf-8") as f:
                                f.write(dublaj_source)
                            logger.info("Dublaj source2.php içeriği 'dublaj_source2_debug.html' dosyasına kaydedildi.")
                        except Exception as e:
                            logger.error(f"Dublaj source2.php içeriği kaydedilemedi: {e}")

                        dublaj_extract_match = re.search(r'"file":"([^"]+)"', dublaj_source)
                        if dublaj_extract_match:
                            dublaj_link = dublaj_extract_match.group(1).replace("\\", "")
                            logger.info(f"ContentX: Türkçe dublaj linki bulundu: {dublaj_link}")
                            linkler.append({
                                "kaynak": "ContentX (Dublaj)", 
                                "isim": "ContentX Dublaj", 
                                "url": dublaj_link, 
                                "tur": "m3u8"
                            })
                            if callback:
                                await callback(linkler[-1])
                    except Exception as e:
                        logger.error(f"ContentX: Dublaj source2.php isteği başarısız: {e}")

                # Sonuçları döndür
                await browser.close()
                return {"linkler": linkler, "altyazilar": altyazilar}

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
                context = await browser.new_context(
                    user_agent=HEADERS["User-Agent"],
                    bypass_csp=True,
                    java_script_enabled=True,
                    ignore_https_errors=True,
                    viewport={"width": 1920, "height": 1080}
                )
                await stealth_async(context)
                page = await context.new_page()
                try:
                    await page.goto(self.main_url, timeout=120000)
                    await page.wait_for_selector("input[name=cKey]", state="attached", timeout=60000)
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    context = await browser.new_context(
                        user_agent=HEADERS["User-Agent"],
                        bypass_csp=True,
                        java_script_enabled=True,
                        ignore_https_errors=True,
                        viewport={"width": 1920, "height": 1080}
                    )
                    await stealth_async(context)
                    page = await context.new_page()
                    await page.goto(self.main_url, timeout=120000)
                    await page.wait_for_selector("input[name=cKey]", state="attached", timeout=60000)

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
        await self.init_session()
        async with async_playwright() as p:
            browser = None
            try:
                browser = await p.firefox.launch(headless=True, proxy=PROXY)
                context = await browser.new_context(
                    user_agent=HEADERS["User-Agent"],
                    bypass_csp=True,
                    java_script_enabled=True,
                    ignore_https_errors=True,
                    viewport={"width": 1920, "height": 1080}
                )
                await stealth_async(context)
                for name, value in self.session_cookies.items():
                    await context.add_cookies([{
                        "name": name, 
                        "value": value, 
                        "url": self.main_url,
                        "domain": urlparse(self.main_url).hostname,
                        "path": "/"
                    }])
                page = await context.new_page()
                try:
                    logger.info(f"Link sayfasına erişiliyor: {data}")
                    await page.goto(data, timeout=120000)
                    await page.wait_for_selector("div[data-rm-k]", state="attached", timeout=60000)
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    context = await browser.new_context(
                        user_agent=HEADERS["User-Agent"],
                        bypass_csp=True,
                        java_script_enabled=True,
                        ignore_https_errors=True,
                        viewport={"width": 1920, "height": 1080}
                    )
                    await stealth_async(context)
                    for name, value in self.session_cookies.items():
                        await context.add_cookies([{
                            "name": name, 
                            "value": value, 
                            "url": self.main_url,
                            "domain": urlparse(self.main_url).hostname,
                            "path": "/"
                        }])
                    page = await context.new_page()
                    await page.goto(data, timeout=120000)
                    await page.wait_for_selector("div[data-rm-k]", state="attached", timeout=60000)

                # Kotlin'deki hiddenJson çıkarma mantığı
                content = await page.content()
                soup = BeautifulSoup(content, 'html.parser')
                hidden_json_tag = soup.select_one("div[data-rm-k]")
                
                if not hidden_json_tag:
                    # Hata ayıklama için sayfa kaynağını kaydet
                    timestamp = int(time.time())
                    filename = f"error_{timestamp}.html"
                    with open(filename, "w", encoding="utf-8") as f:
                        f.write(content)
                    logger.error(f"Şifreli JSON verisi 'div[data-rm-k]' içinde bulunamadı. Sayfa kaynağı '{filename}' dosyasına kaydedildi.")
                    await browser.close()
                    return False

                hidden_json = hidden_json_tag.text
                logger.info(f"Şifreli JSON bulundu: {hidden_json[:100]}...")
                
                try:
                    # JSON'daki gereksiz karakterleri temizle
                    hidden_json = re.sub(r'[\x00-\x1F\x7F]', '', hidden_json)
                    obj = json.loads(hidden_json)
                    
                    ciphertext = obj['ciphertext']
                    iv = obj['iv']
                    salt = obj['salt']
                except json.JSONDecodeError as e:
                    logger.error(f"JSON parse hatası: {e}\nHam JSON: {hidden_json}")
                    await browser.close()
                    return False
                except KeyError as e:
                    logger.error(f"JSON eksik anahtar hatası: {e}\nJSON: {obj}")
                    await browser.close()
                    return False
                
                passphrase = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
                
                try:
                    decrypted_content = decrypt(passphrase, salt, iv, ciphertext)
                    logger.info(f"Çözülen içerik: {decrypted_content[:100]}...")
                    
                    iframe_url = urljoin(self.main_url, decrypted_content) if not decrypted_content.startswith("http") else decrypted_content
                    logger.info(f"Çözülen iframe URL: {iframe_url}")
                    
                    for extractor in self.extractors:
                        result = await extractor.get_url(
                            iframe_url, 
                            referer=data, 
                            subtitle_callback=subtitle_callback, 
                            callback=callback, 
                            context=context
                        )
                        if result["linkler"]:
                            await browser.close()
                            return True
                except Exception as e:
                    logger.error(f"Şifre çözme veya iframe işleme hatası: {e}")
                
                await browser.close()
                return False

            except Exception as e:
                logger.error(f"Link çıkarma hatası: {e}")
                if browser:
                    await browser.close()
                return False

    async def calistir(self):
        """Ana sayfadan dizileri kazı ve JSON olarak kaydet."""
        await self.init_session()
        url = f"{self.main_url}/yabanci-dizi-izle"
        async with async_playwright() as p:
            browser = None
            try:
                browser = await p.firefox.launch(headless=True, proxy=PROXY)
                context = await browser.new_context(
                    user_agent=HEADERS["User-Agent"],
                    bypass_csp=True,
                    java_script_enabled=True,
                    ignore_https_errors=True,
                    viewport={"width": 1920, "height": 1080}
                )
                await stealth_async(context)
                
                # Oturum çerezlerini ekle
                for name, value in self.session_cookies.items():
                    await context.add_cookies([{
                        "name": name, 
                        "value": value, 
                        "url": self.main_url,
                        "domain": urlparse(self.main_url).hostname,
                        "path": "/"
                    }])
                
                page = await context.new_page()
                try:
                    logger.info(f"Ana sayfaya erişiliyor: {url}")
                    await page.goto(url, timeout=120000)
                    await page.wait_for_selector("div.prm-borderb", state="attached", timeout=60000)
                except Exception as e:
                    logger.warning(f"Proxy ile erişim başarısız, proxysiz deneniyor: {e}")
                    await browser.close()
                    browser = await p.firefox.launch(headless=True)
                    context = await browser.new_context(
                        user_agent=HEADERS["User-Agent"],
                        bypass_csp=True,
                        java_script_enabled=True,
                        ignore_https_errors=True,
                        viewport={"width": 1920, "height": 1080}
                    )
                    await stealth_async(context)
                    for name, value in self.session_cookies.items():
                        await context.add_cookies([{
                            "name": name, 
                            "value": value, 
                            "url": self.main_url,
                            "domain": urlparse(self.main_url).hostname,
                            "path": "/"
                        }])
                    page = await context.new_page()
                    await page.goto(url, timeout=120000)
                    await page.wait_for_selector("div.prm-borderb", state="attached", timeout=60000)

                content = await page.content()
                soup = BeautifulSoup(content, 'html.parser')
                series_divs = soup.select("div.prm-borderb")
                logger.info(f"Ana sayfada bulunan öğe sayısı: {len(series_divs)}")
                
                all_data = []
                processed_series_urls = set()

                # TEST İÇİN: Sadece ilk 1 diziyi işle
                for item in series_divs[:1]:
                    try:
                        a_tag = item.select_one("a")
                        if not a_tag:
                            continue
                            
                        raw_href = a_tag.get("href", "")
                        # Kotlin'deki href dönüşüm mantığı
                        if "/bolum/" in raw_href:
                            series_href = "/series/" + re.sub(r'-\d+x.*$', '', raw_href.split('/')[2])
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

                        await page.goto(series_url, timeout=120000)
                        try:
                            # Daha esnek bekleme stratejisi
                            await page.wait_for_selector("a.text.block", state="attached", timeout=60000)
                        except Exception as e:
                            logger.error(f"Bölüm listesi yüklenirken zaman aşımı: {e}")
                            # Bir sonraki diziye geç
                            continue
                        
                        series_content = await page.content()
                        series_soup = BeautifulSoup(series_content, 'html.parser')
                        episode_links = series_soup.select("a.text.block[data-dizipal-pageloader='true']")
                        logger.info(f"  > {len(episode_links)} bölüm bulundu.")

                        series_data = {"baslik": title, "url": series_url, "bolumler": []}
                        
                        # TEST İÇİN: Sadece ilk 1 bölümü işle
                        for ep_link in episode_links[:1]:
                            episode_url = urljoin(self.main_url, ep_link['href'])
                            video_data = {"linkler": [], "altyazilar": []}
                            
                            async def subtitle_callback(subtitle):
                                video_data["altyazilar"].append(subtitle)
                            
                            async def link_callback(link):
                                video_data["linkler"].append(link)
                            
                            logger.info(f"Bölüm işleniyor: {episode_url}")
                            success = await self.load_links(
                                episode_url, 
                                False, 
                                subtitle_callback, 
                                link_callback
                            )
                            
                            if success:
                                series_data["bolumler"].append({
                                    "url": episode_url, 
                                    "video_bilgisi": video_data
                                })
                            else:
                                logger.warning(f"Bölüm için link bulunamadı: {episode_url}")

                        all_data.append(series_data)

                    except Exception as e:
                        logger.error(f"Seri işlenirken hata: {e}")

                await browser.close()
                with open("dizipal_sonuclar.json", "w", encoding="utf-8") as f:
                    json.dump(all_data, f, ensure_ascii=False, indent=4)
                logger.info("Veriler 'dizipal_sonuclar.json' dosyasına kaydedildi.")

            except Exception as e:
                logger.error(f"Ana sayfa kazıma hatası: {e}")
                if browser:
                    await browser.close()

# Ana çalıştırma
if __name__ == "__main__":
    dizipal = DiziPalOrijinal()
    asyncio.run(dizipal.calistir())
