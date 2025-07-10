import asyncio
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
import random
import time # sleep için kullanılacak
from playwright.async_api import async_playwright
from playwright_stealth import stealth_async
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import base64
import logging

try:
    import cloudscraper
except ImportError:
    cloudscraper = None

# Loglama ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Proxy ayarları (Bulduğunuz yeni ve daha gelişmiş proxy'nizi buraya girin)
# Örnek: "http://kullanici:sifre@proxy.adres:port" veya "socks5://proxy.adres:port"
PROXY = {
    "server": "socks5://45.89.28.226:12915", # Burayı yeni proxy'nizle güncelleyin
    # Eğer proxy'niz kimlik doğrulama gerektiriyorsa 'username' ve 'password' ekleyin
    # "username": "your_proxy_username",
    # "password": "your_proxy_password",
}
# PROXY = None # Proxy kullanmıyorsanız bu satırı aktif edin

# Başlık ayarları
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
    "Accept-Language": "en-US,en;q=0.5", # Gerçekçi bir dil tercihi
    "Connection": "keep-alive",
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

class ContentX(ExtractorApi):
    name = "ContentX"
    main_url = "https://contentx.me"
    requires_referer = True

    async def get_url(self, url, referer=None, subtitle_callback=None, callback=None, context=None):
        headers = HEADERS.copy()
        if referer:
            headers["Referer"] = referer

        async with async_playwright() as p:
            browser = None
            try:
                # Headless modunu True veya False olarak test edebilirsiniz
                browser_options = {'headless': True} 
                if PROXY:
                    browser_options['proxy'] = PROXY
                    
                browser = await p.firefox.launch(**browser_options)
                # Yeni bir tarayıcı bağlamı oluşturmak, çerezleri ve yerel depolamayı izole eder
                # user_agent de burada ayarlanıyor
                page_context = context or await browser.new_context(user_agent=HEADERS["User-Agent"])
                
                # Playwright Stealth ile ek gizlenme
                await stealth_async(page_context)

                # Ek WebGL parmak izi gizleme (Playwright Stealth'in bir parçası olabilir ancak manuel kontrol faydalı)
                await page_context.add_init_script("""
                    Object.defineProperty(WebGLRenderingContext.prototype, 'getParameter', {
                        value: function(parameter) {
                            // UNMASKED_VENDOR_WEBGL
                            if (parameter === 37445) {
                                return 'Google Inc.';
                            }
                            // UNMASKED_RENDERER_WEBGL
                            if (parameter === 37446) {
                                return 'ANGLE (Google, Vulkan)'; 
                            }
                            return this.originalGetParameter(parameter);
                        }
                    });
                    WebGLRenderingContext.prototype.originalGetParameter = WebGLRenderingContext.prototype.getParameter;
                """)
                
                page = await page_context.new_page()

                logger.info(f"ContentX: Iframe URL'sine gidiliyor: {url} (Referer: {referer})")
                
                # İnsanvari bekleme süresi
                await asyncio.sleep(random.uniform(2, 5)) 
                
                # 'networkidle' daha kapsamlı bir bekleme stratejisi
                await page.goto(url, timeout=90000, wait_until="networkidle", referer=referer) 
                
                # Sayfanın tamamen yüklendiğinden ve JavaScript'lerin çalıştığından emin olmak için ek gecikme
                await asyncio.sleep(random.uniform(3, 7)) 

                i_source = await page.content()

                linkler = []
                altyazilar = []

                # 1. Altyazıları ayıkla
                sub_urls = set()
                for match in re.finditer(r'"file":"((?:\\"|[^"])+)","label":"((?:\\"|[^"])+)"', i_source, re.IGNORECASE):
                    sub_url = match.group(1).replace("\\/", "/").replace("\\u0026", "&").replace("\\", "")
                    sub_lang = match.group(2).replace("\\u0131", "ı").replace("\\u0130", "İ").replace("\\u00fc", "ü").replace("\\u00e7", "ç").replace("\\u011f", "ğ").replace("\\u015f", "ş")
                    if sub_url not in sub_urls:
                        sub_urls.add(sub_url)
                        altyazilar.append({"dil": sub_lang, "url": urljoin(self.main_url, sub_url)})
                        if subtitle_callback:
                            await subtitle_callback(altyazilar[-1])
                logger.info(f"Altyazılar: {sub_urls}")

                # 2. 'window.openPlayer' parametresini ayıkla
                open_player_match = re.search(r"window\.openPlayer\('([^']+)'\)", i_source, re.IGNORECASE)
                
                if open_player_match:
                    i_extract_val = open_player_match.group(1)
                    parsed_url = urlparse(url)
                    base_iframe_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
                    
                    # 3. source2.php adresine yeni bir istek gönder
                    source_url = f"{base_iframe_url}/source2.php?v={i_extract_val}"
                    logger.info(f"ContentX: source2.php adresine istek gönderiliyor: {source_url} (Referer: {url})")

                    # İnsanvari bekleme süresi
                    await asyncio.sleep(random.uniform(2, 4))

                    await page.goto(source_url, timeout=90000, wait_until="domcontentloaded", referer=url)
                    vid_source = await page.content()

                    # 4. Gelen cevaptan asıl video linkini ayıkla
                    vid_extract_match = re.search(r'"file":"((?:\\"|[^"])+)"', vid_source, re.IGNORECASE)
                    if vid_extract_match:
                        m3u_link = vid_extract_match.group(1).replace("\\", "")
                        logger.info(f"ContentX: BAŞARILI! Video linki bulundu: {m3u_link}")
                        linkler.append({"kaynak": "ContentX (Source2)", "isim": "ContentX Video", "url": m3u_link, "tur": "m3u8"})
                        if callback:
                            await callback(linkler[-1])
                    else:
                        logger.warning(f"ContentX: source2.php cevabında video linki bulunamadı. İçerik: {vid_source[:200]}")
                
                else:
                    logger.warning(f"ContentX: 'window.openPlayer' parametresi iframe içinde bulunamadı. URL: {url}")

                await browser.close()
                return {"linkler": linkler, "altyazilar": altyazilar}

            except Exception as e:
                logger.error(f"ContentX çıkarma işlemi sırasında bir hata oluştu: {e}")
                if browser:
                    await browser.close()
                return {"linkler": [], "altyazilar": []}

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
        self.dizipal_referer = self.main_url + "/" 
        HEADERS['Referer'] = self.dizipal_referer

    async def init_session(self):
        if self.session_cookies and self.c_key and self.c_value:
            return
        logger.info("Oturum başlatılıyor: çerezler, cKey ve cValue alınıyor")
        async with async_playwright() as p:
            browser = None
            try:
                browser_options = {'headless': True}
                if PROXY:
                    browser_options['proxy'] = PROXY
                    
                browser = await p.firefox.launch(**browser_options)
                context = await browser.new_context(user_agent=HEADERS["User-Agent"]) # context içinde user_agent ayarı
                await stealth_async(context)
                
                # Klavye ve fare davranışını taklit etmek için ek başlangıç scripti
                await context.add_init_script("""
                    // Rastgele klavye gecikmeleri
                    const originalType = HTMLInputElement.prototype.type;
                    HTMLInputElement.prototype.type = async function(...args) {
                        const delay = Math.random() * 100 + 50; // 50-150ms arası
                        await new Promise(r => setTimeout(r, delay));
                        return originalType.apply(this, args);
                    };

                    // Rastgele fare hareketleri ve tıklama gecikmeleri
                    const originalClick = HTMLElement.prototype.click;
                    HTMLElement.prototype.click = async function(...args) {
                        const delay = Math.random() * 200 + 100; // 100-300ms arası
                        await new Promise(r => setTimeout(r, delay));
                        return originalClick.apply(this, args);
                    };
                """)

                page = await context.new_page()
                
                logger.info(f"Dizipal ana sayfasına gidiliyor: {self.main_url}")
                await page.goto(self.main_url, timeout=90000, wait_until="load")
                
                # Cloudflare'ı aşmak için ek gecikme ve rastgele bir kaydırma yapma
                await asyncio.sleep(random.uniform(5, 10))
                # Sayfayı rastgele kaydırma
                await page.evaluate('window.scrollBy(0, document.body.scrollHeight / 2)')
                await asyncio.sleep(random.uniform(1, 3))
                await page.evaluate('window.scrollBy(0, -document.body.scrollHeight / 4)')
                await asyncio.sleep(random.uniform(1, 3))


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
                browser_options = {'headless': True}
                if PROXY:
                    browser_options['proxy'] = PROXY
                
                browser = await p.firefox.launch(**browser_options)
                context = await browser.new_context(user_agent=HEADERS["User-Agent"]) # context içinde user_agent ayarı
                await stealth_async(context)

                # init_session'dan kopyalanan init_scripts'leri de buraya ekliyoruz
                await context.add_init_script("""
                    const originalType = HTMLInputElement.prototype.type;
                    HTMLInputElement.prototype.type = async function(...args) {
                        const delay = Math.random() * 100 + 50; 
                        await new Promise(r => setTimeout(r, delay));
                        return originalType.apply(this, args);
                    };
                    const originalClick = HTMLElement.prototype.click;
                    HTMLElement.prototype.click = async function(...args) {
                        const delay = Math.random() * 200 + 100; 
                        await new Promise(r => setTimeout(r, delay));
                        return originalClick.apply(this, args);
                    };
                    Object.defineProperty(WebGLRenderingContext.prototype, 'getParameter', {
                        value: function(parameter) {
                            if (parameter === 37445) { return 'Google Inc.'; }
                            if (parameter === 37446) { return 'ANGLE (Google, Vulkan)'; }
                            return this.originalGetParameter(parameter);
                        }
                    });
                    WebGLRenderingContext.prototype.originalGetParameter = WebGLRenderingContext.prototype.getParameter;
                """)

                if self.session_cookies:
                    await context.add_cookies([{"name": name, "value": value, "url": self.main_url} for name, value in self.session_cookies.items()])
                
                page = await context.new_page()
                
                logger.info(f"Link sayfasına erişiliyor: {data}")
                await asyncio.sleep(random.uniform(2, 5)) # İnsanvari gecikme
                await page.goto(data, timeout=90000, wait_until="load")

                # Sayfayı kaydırma ve biraz bekleme
                await asyncio.sleep(random.uniform(3, 7))
                await page.evaluate('window.scrollBy(0, document.body.scrollHeight / 3)')
                await asyncio.sleep(random.uniform(1, 3))
                await page.evaluate('window.scrollBy(0, -document.body.scrollHeight / 6)')
                await asyncio.sleep(random.uniform(1, 3))

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

                # İframe işleme işlemini extractor'e devret
                for extractor in self.extractors:
                    result = await extractor.get_url(iframe_url, referer=self.dizipal_referer, subtitle_callback=subtitle_callback, callback=callback, context=context)
                    if result and (result.get("linkler") or result.get("altyazilar")):
                        await browser.close()
                        return True
                
                logger.warning("Tüm extractor'lar denendi ancak link bulunamadı.")
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
        # Örnek olarak tek bir bölümü test edelim
        ornek_bolum_url = "https://dizipal935.com/bolum/yesilcam-1x1" 
        
        logger.info(f"Tek bölüm testi başlatılıyor: {ornek_bolum_url}")

        video_data = {"linkler": [], "altyazilar": []}
        async def subtitle_callback(subtitle):
            logger.info(f"Altyazı bulundu: {subtitle}")
            video_data["altyazilar"].append(subtitle)
        async def callback(link):
            logger.info(f"Video linki bulundu: {link}")
            video_data["linkler"].append(link)
        
        success = await self.load_links(ornek_bolum_url, False, subtitle_callback, callback)
        
        if success and video_data["linkler"]:
            logger.info("\n--- TEST BAŞARILI ---")
            logger.info(f"Bulunan Video Linkleri: {json.dumps(video_data['linkler'], indent=2)}")
            logger.info(f"Bulunan Altyazılar: {json.dumps(video_data['altyazilar'], indent=2)}")
        else:
            logger.error("\n--- TEST BAŞARISIZ ---")
            logger.error("Video linki veya altyazı bulunamadı.")

# Ana çalıştırma
if __name__ == "__main__":
    dizipal = DiziPalOrijinal()
    asyncio.run(dizipal.calistir())
