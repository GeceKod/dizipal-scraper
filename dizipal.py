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
def decrypt(passphraze, salt_hex, iv_hex, ciphertext_base64):
    try:
        salt = bytes.fromhex(salt_hex)
        iv = bytes.fromhex(iv_hex)
        ciphertext = base64.b64decode(ciphertext_base64)
        key = PBKDF2(passphraze, salt, dkLen=32, count=999, hmac_hash_module=SHA512)
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
            linkler = []
            altyazilar = []
            try:
                browser_options = {'headless': True}
                if PROXY:
                    browser_options['proxy'] = PROXY
                
                browser = await p.firefox.launch(**browser_options)
                page_context = await browser.new_context(user_agent=HEADERS["User-Agent"])
                await stealth_async(page_context)
                page = await page_context.new_page()

                # Console loglarını yakalamak için listener ekle (debug amaçlı)
                page.on("console", lambda msg: logger.info(f"Tarayıcı Konsolu ({msg.type}): {msg.text}"))
                page.on("pageerror", lambda err: logger.error(f"Tarayıcı Sayfa Hatası: {err}"))
                page.on("requestfailed", lambda request: logger.warning(f"Tarayıcı İstek Hatası: {request.url} - {request.failure().error_text}"))

                # Video linkini yakalamak için bir Future nesnesi oluştur
                video_link_future = asyncio.Future()

                # Ağ isteklerini dinle
                async def handle_response(response):
                    # Video uzantılarını veya source2.php gibi video bilgisi veren URL'leri ara
                    if (re.search(r'\.(m3u8|mp4|ts)(\?|$)', response.url, re.IGNORECASE) or
                        "source2.php?v=" in response.url):
                        
                        try:
                            # Yanıtın metin içeriğini al
                            response_text = await response.text()
                            # Eğer yanıt bir JSON ise ve "file" anahtarı içeriyorsa
                            if response.headers.get("content-type") and "application/json" in response.headers["content-type"]:
                                try:
                                    json_data = json.loads(response_text)
                                    if "file" in json_data:
                                        m3u_link = json_data["file"].replace("\\", "")
                                        if not video_link_future.done():
                                            video_link_future.set_result(m3u_link)
                                            logger.info(f"ContentX: Ağ isteğinden video linki yakalandı (JSON): {m3u_link}")
                                except json.JSONDecodeError:
                                    pass # JSON değilse veya format hatalıysa devam et
                            
                            # Eğer yanıt doğrudan m3u8 veya mp4 linki ise
                            elif re.search(r'\.(m3u8|mp4|ts)(\?|$)', response.url, re.IGNORECASE):
                                if not video_link_future.done():
                                    video_link_future.set_result(response.url)
                                    logger.info(f"ContentX: Doğrudan video URL'si yakalandı: {response.url}")

                        except Exception as e:
                            logger.warning(f"ContentX: Ağ yanıtını işlerken hata: {e}")

                page.on("response", handle_response)

                logger.info(f"ContentX: Iframe URL'sine gidiliyor: {url}")
                # Sayfanın tüm kaynakları yüklenene kadar bekle
                await page.goto(url, timeout=180000, wait_until="networkidle", referer=referer) # Timeout 180 saniyeye çıkarıldı

                # Video linkinin bulunmasını bekle (veya belirli bir süre sonra zaman aşımına uğra)
                try:
                    # Maksimum 60 saniye boyunca video linkinin bulunmasını bekle
                    final_video_link = await asyncio.wait_for(video_link_future, timeout=60)
                    logger.info(f"ContentX: Son video linki başarıyla alındı: {final_video_link}")
                    linkler.append({"kaynak": "ContentX (Network)", "isim": "ContentX Video", "url": final_video_link, "tur": "m3u8"})
                    if callback:
                        await callback(linkler[-1])
                    return {"linkler": linkler, "altyazilar": altyazilar} # Link bulundu, buradan dön
                except asyncio.TimeoutError:
                    logger.warning("ContentX: Belirtilen süre içinde video linki ağ isteklerinden yakalanamadı.")
                    # Eğer ağdan yakalanamazsa, boş listelerle dön
                    return {"linkler": linkler, "altyazilar": altyazilar}
                
            except Exception as e:
                logger.error(f"ContentX çıkarma işlemi sırasında bir hata oluştu: {e}", exc_info=True)
                if browser:
                    await browser.close()
                return {"linkler": linkler, "altyazilar": altyazilar}
            finally:
                if browser:
                    await browser.close()

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
