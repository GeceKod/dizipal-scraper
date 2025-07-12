import asyncio
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import re
import json
import logging
import requests

# Selenium için gerekli kütüphaneler
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
import undetected_chromedriver as uc
from selenium.common.exceptions import TimeoutException, WebDriverException

# Playwright için gerekli kütüphaneler (init_session'da hala kullanılıyor)
from playwright.async_api import async_playwright # Bu satırın varlığı ve doğruluğu önemli!

# Loglama ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Proxy ayarları (Selenium için farklı yapılandırılabilir)
# undetected_chromedriver proxy desteği doğrudan argümanlarla sağlanır.
PROXY_SERVER = "45.89.28.226:12915" # SOCKS5 proxy için sadece IP:Port

# Başlık ayarları (Selenium için User-Agent doğrudan ayarlanır)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
}

# Şifre çözme fonksiyonu
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import base64

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
        driver = None
        linkler = []
        altyazilar = []
        try:
            # undetected_chromedriver seçenekleri
            options = uc.ChromeOptions()
            options.add_argument("--headless") # Headless modda çalıştır
            options.add_argument("--no-sandbox")
            options.add_argument("--disable-dev-shm-usage")
            options.add_argument(f"user-agent={HEADERS['User-Agent']}")
            
            # Proxy ayarı
            if PROXY_SERVER:
                options.add_argument(f'--proxy-server=socks5://{PROXY_SERVER}')

            # Tarayıcıyı başlat
            logger.info("ContentX: Selenium ile Chrome başlatılıyor...")
            driver = uc.Chrome(options=options)
            driver.set_page_load_timeout(90) # Sayfa yükleme zaman aşımı

            logger.info(f"ContentX: Iframe URL'sine gidiliyor: {url}")
            driver.get(url)

            # Cloudflare veya dinamik içeriğin yüklenmesini bekle
            try:
                WebDriverWait(driver, 60).until(
                    lambda d: d.execute_script("return document.readyState") == "complete"
                )
                logger.info("ContentX: Sayfa yüklemesi tamamlandı.")
            except TimeoutException:
                logger.warning("ContentX: Sayfa yüklemesi zaman aşımına uğradı, ancak devam ediliyor.")
            except Exception as e:
                logger.error(f"ContentX: Sayfa yüklemesi sırasında hata: {e}")
                driver.quit()
                return {"linkler": linkler, "altyazilar": altyazilar}

            i_source = driver.page_source
            logger.info(f"ContentX: Iframe içeriği (i_source) - Tamamı:\n{i_source}")
            
            # Kotlin kodundaki regex'e benzer şekilde tek veya çift tırnak için esnek regex kullanıyoruz.
            open_player_match = re.search(r"window\.openPlayer\(['\"]([^'\"]+)['\"]\)", i_source, re.IGNORECASE)
            
            if open_player_match:
                i_extract_val = open_player_match.group(1)
                logger.info(f"ContentX: Regex ile alınan parametre: {i_extract_val}")
                parsed_url = urlparse(url)
                base_iframe_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                
                source_url = f"{base_iframe_url}/source2.php?v={i_extract_val}"
                logger.info(f"ContentX: source2.php adresine istek gönderiliyor: {source_url}")

                # source2.php adresine git ve içeriğini al
                driver.get(source_url)
                vid_source = driver.page_source

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
                logger.warning(f"ContentX: 'window.openPlayer' parametresi regex ile bulunamadı.")

            driver.quit()
            return {"linkler": linkler, "altyazilar": altyazilar}

        except WebDriverException as e:
            logger.error(f"ContentX Selenium WebDriver hatası: {e}", exc_info=True)
            if driver:
                driver.quit()
            return {"linkler": linkler, "altyazilar": altyazilar}
        except Exception as e:
            logger.error(f"ContentX çıkarma işlemi sırasında genel hata: {e}", exc_info=True)
            if driver:
                driver.quit()
            return {"linkler": linkler, "altyazilar": altyazilar}

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
        # Ana sayfa için hala Playwright kullanıyoruz
        # async_playwright'ın import edildiğinden emin olmalıyız.
        # En üstte import edilmiş durumda.
        async with async_playwright() as p:
            browser = None
            try:
                browser_options = {'headless': True}
                if PROXY_SERVER: # Playwright için proxy ayarı
                    browser_options['proxy'] = {"server": f"socks5://{PROXY_SERVER}"}
                    
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
        
        # Bu kısım hala Playwright kullanıyor, çünkü ana sayfa oturumu burada başlatılıyor.
        # Sadece ContentX extractor'ını Selenium'a taşıdık.
        async with async_playwright() as p: # Bu blok içinde async_playwright kullanılıyor
            browser = None
            try:
                browser_options = {'headless': True}
                if PROXY_SERVER:
                    browser_options['proxy'] = {"server": f"socks5://{PROXY_SERVER}"}
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
                    # ContentX artık Selenium kullanıyor
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
