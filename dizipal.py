import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json
from playwright.async_api import async_playwright
from playwright_stealth import stealth_async
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import base64
import logging
import requests

# Loglama ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Proxy ayarları
PROXY = {
    "server": "socks5://45.89.28.226:12915"
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
        result = plaintext.decode('utf-8')
        return result
    except Exception as e:
        logger.error(f"Şifre çözme hatası: {str(e)}")
        raise

# Base ExtractorApi sınıfı
class ExtractorApi:
    async def get_url(self, url, referer=None, subtitle_callback=None, callback=None, context=None):
        raise NotImplementedError

class ContentX(ExtractorApi):
    name = "ContentX"
    main_url = "https://contentx.me"
    requires_referer = True

    async def get_url(self, url, referer=None, subtitle_callback=None, callback=None, context=None):
        async with async_playwright() as p:
            browser = None
            try:
                browser_options = {'headless': True}
                if PROXY:
                    browser_options['proxy'] = PROXY
                
                browser = await p.firefox.launch(**browser_options)
                page_context = await browser.new_context(user_agent=HEADERS["User-Agent"])
                await stealth_async(page_context)
                page = await page_context.new_page()

                logger.info(f"ContentX: Iframe URL'sine gidiliyor: {url}")
                await page.goto(url, timeout=90000, wait_until="networkidle", referer=referer)

                try:
                    logger.info("iFrame içindeki Cloudflare koruması bekleniyor...")
                    # window.openPlayer fonksiyonunun tanımlanmasını bekle
                    await page.wait_for_function("() => window.openPlayer !== undefined", timeout=90000)
                    logger.info("Cloudflare koruması başarıyla geçildi, 'window.openPlayer' script'i bulundu.")
                except Exception as e:
                    logger.error(f"Bekleme süresi doldu, 'window.openPlayer' script'i bulunamadı. Sayfa Cloudflare'de takılmış olabilir. Hata: {e}")
                    await page.screenshot(path='cloudflare_error_iframe.png')
                    await browser.close()
                    return {"linkler": [], "altyazilar": []}

                # DEĞİŞİKLİK BAŞLANGICI: page.evaluate kullanarak parametreyi doğrudan alma
                logger.info("ContentX: 'window.openPlayer' parametresi için page.evaluate çalıştırılıyor...")
                i_extract_val = await page.evaluate('''() => {
                    // Sayfanın tüm HTML içeriğini al
                    const scriptContent = document.documentElement.outerHTML;
                    // window.openPlayer çağrısını ve içindeki parametreyi regex ile bul
                    const match = scriptContent.match(/window\\.openPlayer\\(['"]([^'"]+)['"]\\)/);
                    if (match && match[1]) {
                        return match[1]; // Parametreyi döndür
                    }
                    return null; // Bulunamazsa null döndür
                }''')

                if i_extract_val:
                    logger.info(f"ContentX: page.evaluate ile alınan parametre: {i_extract_val}")
                    parsed_url = urlparse(url)
                    base_iframe_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    
                    source_url = f"{base_iframe_url}/source2.php?v={i_extract_val}"
                    logger.info(f"ContentX: source2.php adresine istek gönderiliyor: {source_url}")

                    await page.goto(source_url, timeout=90000, wait_until="networkidle", referer=url)
                    vid_source = await page.content()

                    vid_extract_match = re.search(r'"file":"((?:\\"|[^"])+)"', vid_source, re.IGNORECASE)
                    if vid_extract_match:
                        m3u_link = vid_extract_match.group(1).replace("\\", "")
                        logger.info(f"ContentX: BAŞARILI! Video linki bulundu: {m3u_link}")
                        linkler.append({"kaynak": "ContentX (Source2)", "isim": "ContentX Video", "url": m3u_link, "tur": "m3u8"})
                        if callback:
                            await callback(linkler[-1])
                    else:
                        logger.warning(f"ContentX: source2.php cevabında video linki bulunamadı.")
                else:
                    logger.warning(f"ContentX: 'window.openPlayer' parametresi page.evaluate ile bulunamadı.")
                # DEĞİŞİKLİK SONU

                await browser.close()
                return {"linkler": linkler, "altyazilar": altyazilar}

            except Exception as e:
                logger.error(f"ContentX çıkarma işlemi sırasında bir hata oluştu: {e}", exc_info=True)
                if browser:
                    await browser.close()
                return {"linkler": [], "altyazilar": []}

class DiziPalOrijinal:
    main_url = "https://dizipal935.com"
    name = "DiziPalOrijinal"
    lang = "tr"

    def __init__(self):
        self.session_cookies = None
        self.c_key = None
        self.c_value = None
        self.extractors = [ContentX()]
        HEADERS['Referer'] = self.main_url + "/"

    async def init_session(self):
        if hasattr(self, '_session_initialized') and self._session_initialized:
            return
            
        logger.info("Oturum başlatılıyor: çerezler, cKey ve cValue alınıyor")
        async with async_playwright() as p:
            browser = None
            try:
                browser_options = {'headless': True}
                if PROXY:
                    browser_options['proxy'] = PROXY
                    
                browser = await p.firefox.launch(**browser_options)
                context = await browser.new_context(user_agent=HEADERS["User-Agent"])
                await stealth_async(context)
                page = await context.new_page()
                
                logger.info(f"Ana sayfa ({self.main_url}) açılıyor...")
                await page.goto(self.main_url, timeout=90000, wait_until="domcontentloaded")

                logger.info("Ana sayfadaki bot korumasının çözülmesi için 15 saniye bekleniyor...")
                await page.wait_for_timeout(15000)

                page_content = await page.content()
                soup = BeautifulSoup(page_content, 'html.parser')

                self.session_cookies = {cookie["name"]: cookie["value"] for cookie in await context.cookies()}
                self.c_key = soup.select_one("input[name=cKey]")['value'] if soup.select_one("input[name=cKey]") else None
                self.c_value = soup.select_one("input[name=cValue]")['value'] if soup.select_one("input[name=cValue]") else None
                
                if not self.c_key or not self.c_value:
                    print("\n" + "="*80 + "\nHATA DEBUG: ANA SAYFA HTML İÇERİĞİ\n" + "-"*80 + f"\n{page_content}\n" + "="*80 + "\n")
                    raise ValueError("cKey veya cValue alınamadı.")
                
                logger.info(f"Oturum bilgileri başarıyla alındı.")
                self._session_initialized = True
                await browser.close()
            except Exception as e:
                logger.error(f"Oturum başlatma başarısız: {e}", exc_info=True)
                if browser:
                    await browser.close()
                raise

    async def load_links(self, data, is_casting, subtitle_callback, callback):
        await self.init_session()
        
        async with async_playwright() as p:
            browser = None
            try:
                browser_options = {'headless': True}
                if PROXY:
                    browser_options['proxy'] = PROXY
                browser = await p.firefox.launch(**browser_options)
                context = await browser.new_context(user_agent=HEADERS["User-Agent"])
                await stealth_async(context)

                if self.session_cookies:
                    await context.add_cookies([{"name": name, "value": value, "url": self.main_url} for name, value in self.session_cookies.items()])
                
                page = await context.new_page()
                
                logger.info(f"Link sayfasına erişiliyor: {data}")
                await page.goto(data, timeout=90000, wait_until="load")
                
                logger.info("Bölüm sayfasındaki şifreli verinin yüklenmesi bekleniyor...")
                await page.wait_for_selector("div[data-rm-k]", state="attached", timeout=60000) 
                
                page_content = await page.content()
                soup = BeautifulSoup(page_content, 'html.parser')

                hidden_json_tag = soup.select_one("div[data-rm-k]")
                if not hidden_json_tag:
                    raise ValueError("Şifreli JSON verisi 'div[data-rm-k]' içinde bulunamadı.")

                obj = json.loads(hidden_json_tag.text) 
                passphrase = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"
                decrypted_content = decrypt(passphrase, obj['salt'], obj['iv'], obj['ciphertext'])
                iframe_url = urljoin(self.main_url, decrypted_content) if not decrypted_content.startswith("http") else decrypted_content
                logger.info(f"Çözülen iframe URL: {iframe_url}")

                await browser.close()

                for extractor in self.extractors:
                    result = await extractor.get_url(iframe_url, referer=data, subtitle_callback=subtitle_callback, callback=callback)
                    if result and result.get("linkler"):
                        return True
                
                logger.warning("Tüm extractor'lar denendi ancak link bulunamadı.")
                return False

            except Exception as e:
                logger.error(f"Link çıkarma hatası: {e}", exc_info=True)
                if browser:
                    await browser.close()
                return False

    async def calistir(self):
        ornek_bolum_url = "https://dizipal935.com/bolum/yesilcam-1x1"
        logger.info(f"Tek bölüm testi başlatılıyor: {ornek_bolum_url}")

        video_data = {"linkler": [], "altyazilar": []}
        async def subtitle_callback(subtitle):
            logger.info(f"Altyazı bulundu: {subtitle}")
            video_data["altyazilar"].append(subtitle)
        async def callback(link):
            logger.info(f"Video linki bulundu: {link}")
            video_data["linkler"].append(link)
        
        try:
            success = await self.load_links(ornek_bolum_url, False, subtitle_callback, callback)
            if success and video_data["linkler"]:
                logger.info("\n--- TEST BAŞARILI ---")
                logger.info(f"Bulunan Video Linkleri: {json.dumps(video_data['linkler'], indent=2, ensure_ascii=False)}")
                logger.info(f"Bulunan Altyazılar: {json.dumps(video_data['altyazilar'], indent=2, ensure_ascii=False)}")
            else:
                logger.error("\n--- TEST BAŞARISIZ ---\nVideo linki veya altyazı bulunamadı.")
        except Exception as e:
            logger.error(f"\n--- TEST BAŞARISIZ ---\nAna programda kritik hata: {e}", exc_info=True)

# Ana çalıştırma
if __name__ == "__main__":
    dizipal = DiziPalOrijinal()
    asyncio.run(dizipal.calistir())
