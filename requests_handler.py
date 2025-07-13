import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options as ChromeOptions
import time
import re
from urllib.parse import unquote # Çerezleri URL dekode etmek için

class RequestHandler:
    def __init__(self):
        self.session = requests.Session()
        self.cf_cookies = {}
        # Kotlin kodunda belirtilen User-Agent'ı kullanıyoruz
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

    def _bypass_cloudflare(self, url):
        print(f"Cloudflare aşıma girişimi: {url} (Selenium ile)...")
        options = ChromeOptions()
        options.add_argument("--headless")  # Tarayıcıyı arkaplanda çalıştır
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(f"user-agent={self.user_agent}")

        driver = None # Hata durumunda driver'ı kapatabilmek için
        try:
            # ChromeDriver'ı otomatik yönet
            driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
            driver.get(url)
            # Cloudflare'ın JavaScript challenge'ını çözmesi için yeterli süre bekle
            # Kotlin kodu "Just a moment" kontrolü yapıyor. Biz de basit bir bekleme süresi kullanıyoruz.
            time.sleep(10) # 10 saniye bekleyelim

            self.cf_cookies = {c['name']: unquote(c['value']) for c in driver.get_cookies()}
            self.user_agent = driver.execute_script("return navigator.userAgent")
            print(f"Cloudflare aş\u0131ld\u0131. \u00C7erezler: {self.cf_cookies}, User-Agent: {self.user_agent}")
            driver.quit()
            return True
        except Exception as e:
            print(f"Cloudflare a\u015Fma ba\u015Far\u0131s\u0131z oldu: {e}")
            if driver:
                driver.quit()
            return False

    def _bypass_ddos_guard(self, url):
        print(f"DDoS-Guard aşıma girişimi: {url}...")
        try:
            # Adım 1: check.js'den ddosBypassPath'i al
            check_js_response = self.session.get("https://check.ddos-guard.net/check.js", timeout=10)
            check_js_response.raise_for_status()
            match = re.search(r"'(.*?)'", check_js_response.text)
            ddos_bypass_path = match.group(1) if match else None

            if not ddos_bypass_path:
                print("check.js içinde ddosBypassPath bulunamadı.")
                return False

            # Adım 2: Bypass path'e istek göndererek çerezleri al
            # URL'in base kısmını alarak bypass path'i ekle
            parsed_url = requests.utils.urlparse(url)
            bypass_url = f"{parsed_url.scheme}://{parsed_url.netloc}{ddos_bypass_path}"
            
            bypass_response = self.session.get(bypass_url, timeout=10)
            bypass_response.raise_for_status()

            # Çerezler requests.Session tarafından otomatik olarak yönetilir
            print(f"DDoS-Guard a\u015F\u0131ld\u0131. Mevcut oturum \u00E7erezleri: {self.session.cookies.get_dict()}")
            return True
        except requests.exceptions.RequestException as e:
            print(f"DDoS-Guard a\u015Fma ba\u015Far\u0131s\u0131z oldu: {e}")
            return False

    def get(self, url, headers=None, allow_redirects=True, timeout=30, handle_protection=True):
        if headers:
            self.session.headers.update(headers)
        self.session.headers.update({'User-Agent': self.user_agent}) # User-Agent'ı her zaman ayarla

        try:
            response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)
            
            # Cloudflare veya DDoS-Guard tespiti
            if handle_protection and (response.status_code in [403, 503] or "Just a moment" in response.text):
                print(f"Koruma tespit edildi {url}. A\u015Fma deneniyor...")
                if "Just a moment" in response.text:
                    if self._bypass_cloudflare(url):
                        # Bypass ba\u015Far\u0131l\u0131 ise orijinal iste\u011Fi tekrar dene
                        # Selenium'dan al\u0131nan \u00E7erezleri oturuma ekle
                        for name, value in self.cf_cookies.items():
                            self.session.cookies.set(name, value)
                        response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)
                elif response.status_code == 403: # Cloudflare metni yoksa DDoS-Guard'a bak
                    if self._bypass_ddos_guard(url):
                        # Bypass ba\u015Far\u0131l\u0131 ise orijinal iste\u011Fi tekrar dene
                        response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)
            
            response.raise_for_status() # HTTP hata durumlar\u0131nda istisna f\u0131rlat
            return response
        except requests.exceptions.RequestException as e:
            print(f"GET iste\u011Fi ba\u015Far\u0131s\u0131z oldu {url}: {e}")
            return None

    def post(self, url, data=None, headers=None, allow_redirects=True, timeout=30):
        if headers:
            self.session.headers.update(headers)
        self.session.headers.update({'User-Agent': self.user_agent})

        try:
            response = self.session.post(url, data=data, allow_redirects=allow_redirects, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"POST iste\u011Fi ba\u015Far\u0131s\u0131z oldu {url}: {e}")
            return None

# Kotlin'deki 'app.get' veya 'app.post' benzeri global bir örnek
request_handler = RequestHandler()
