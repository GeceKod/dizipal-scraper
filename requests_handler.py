import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options as ChromeOptions
import time
import re
from urllib.parse import unquote # Çerezleri URL dekode etmek için
# Selenium için bekleme mekanizmaları
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

class RequestHandler:
    def __init__(self):
        self.session = requests.Session()
        self.cf_cookies = {}
        # Kotlin kodunda belirtilen User-Agent'ı kullanıyoruz
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

        # Proxy ayarlarını buraya ekliyoruz
        # Kullanıcının belirttiği adres: socks5://149.86.137.246:10820
        self.session.proxies = {
            'http': 'socks5://149.86.137.246:10820',
            'https': 'socks5://149.86.137.246:10820'
        }

    def _bypass_cloudflare(self, url):
        print(f"Cloudflare aşıma girişimi: {url} (Selenium ile)...")
        options = ChromeOptions()
        options.add_argument("--headless")  # Tarayıcıyı arkaplanda çalıştır
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(f"user-agent={self.user_agent}")
        # Headless tarayıcı tespitinden kaçınma için ek argümanlar
        options.add_argument("--window-size=1920,1080") # Çözünürlüğü ayarla
        options.add_argument("--start-maximized") # Tam ekran başlat
        options.add_argument("--disable-blink-features=AutomationControlled") # Bot tespitini engelle
        # Otomasyon uzantılarından kaçınmak için deneysel seçenekler
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        
        # Selenium WebDriver'ın da proxy kullanması için bu kısım önemlidir
        # Chromium tabanlı tarayıcılarda --proxy-server argümanı kullanılır
        options.add_argument(f'--proxy-server=socks5://149.86.137.246:10820')


        driver = None # Hata durumunda driver'ı kapatabilmek için
        try:
            # ChromeDriver'ı otomatik yönet
            driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
            
            # navigator.webdriver özelliğini gizleyerek bot tespitinden kaçınma
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                "source": """
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => false
                    });
                """
            })

            driver.get(url)

            # Cloudflare'ın JavaScript challenge'ını çözmesi ve çerezleri ayarlaması için bekle
            # Toplam 30 saniye içinde belirli çerezlerin oluşmasını kontrol et
            max_wait_time = 30 # saniye
            poll_interval = 2 # saniye

            found_cf_cookies = False
            start_time = time.time()

            while time.time() - start_time < max_wait_time:
                current_cookies = driver.get_cookies()
                # cf_clearance veya __cf_bm çerezlerinden biri varsa başarılı say
                if any(c['name'] == 'cf_clearance' or c['name'] == '__cf_bm' for c in current_cookies):
                    self.cf_cookies = {cookie['name']: cookie['value'] for cookie in current_cookies}
                    found_cf_cookies = True
                    break
                time.sleep(poll_interval) # Belirtilen aralıklarla kontrol et

            if not found_cf_cookies:
                print(f"Cloudflare aşma başarısız: {max_wait_time} saniye içinde gerekli Cloudflare çerezleri bulunamadı.")
                return False

            print(f"Cloudflare aşma başarılı. Çerezler alındı: {self.cf_cookies}")
            return True
        except Exception as e:
            print(f"Cloudflare aşma başarısız oldu: {e}")
            return False
        finally:
            if driver:
                driver.quit() # Tarayıcıyı kapat

    def _bypass_ddos_guard(self, url):
        print(f"DDoS-Guard aşıma girişimi: {url}...")
        try:
            # DDoS-Guard'ın JavaScript dosyasını çekerek bypass path'ini bulmaya çalış
            check_js_url = "https://check.ddos-guard.net/check.js"
            js_response = self.session.get(check_js_url, timeout=10)
            js_response.raise_for_status()
            
            # js dosyasından bypass path'ini regex ile çıkar
            match = re.search(r"'(.*?)\'", js_response.text)
            if match:
                bypass_path = match.group(1)
                bypass_url = f"https://{requests.utils.urlparse(url).netloc}{bypass_path}"
                
                print(f"DDoS-Guard bypass URL'si: {bypass_url}")
                bypass_response = self.session.get(bypass_url, timeout=10)
                bypass_response.raise_for_status()

                # Bypass başarılı ise, DDoS-Guard'ın yerleştirdiği çerezleri al
                # Bu çerezler genellikle 'ddos_guard' adında olur
                print(f"DDoS-Guard aşma başarılı. Çerezler alındı: {self.session.cookies.get_dict()}")
                return True
            else:
                print("DDoS-Guard bypass path'i bulunamadı.")
                return False
        except Exception as e:
            print(f"DDoS-Guard aşma başarısız oldu: {e}")
            return False

    def get(self, url, headers=None, allow_redirects=True, timeout=30, handle_protection=False):
        if headers:
            self.session.headers.update(headers)
        # Mevcut çerezleri de isteğe ekleyin
        if self.cf_cookies:
            cookie_header = "; ".join([f"{name}={value}" for name, value in self.cf_cookies.items()])
            self.session.headers.update({'Cookie': cookie_header})
        self.session.headers.update({'User-Agent': self.user_agent})

        try:
            response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)

            # Sadece handle_protection True ise ve 403 veya 503 hatası alırsak bypass denemesi yap
            if handle_protection and (response.status_code == 403 or response.status_code == 503):
                print(f"Koruma tespit edildi {url}. Aşma deneniyor...")
                bypass_successful = False

                # 1. Cloudflare aşma deneniyor
                print(f"Cloudflare aşıma girişimi: {url}...")
                if self._bypass_cloudflare(url):
                    print(f"Cloudflare aşma başarılı: {url}. Orijinal istek tekrarlanıyor...")
                    # Yeni çerezlerle isteği tekrar dene
                    if self.cf_cookies:
                        cookie_header = "; ".join([f"{name}={value}" for name, value in self.cf_cookies.items()])
                        self.session.headers.update({'Cookie': cookie_header})
                    response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)
                    bypass_successful = True
                else:
                    print(f"Cloudflare aşma başarısız oldu: {url}.")

                # 2. Cloudflare aşma başarısız olursa, DDoS-Guard deneniyor
                if not bypass_successful:
                    print(f"DDoS-Guard aşıma girişimi: {url}...")
                    if self._bypass_ddos_guard(url):
                        print(f"DDoS-Guard aşma başarılı: {url}. Orijinal istek tekrarlanıyor...")
                        response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)
                        bypass_successful = True
                    else:
                        print(f"DDoS-Guard aşma başarısız oldu: {url}.")

                if not bypass_successful:
                    print(f"Hiçbir koruma aşma girişimi başarılı olamadı: {url}.")
                    # Eğer bypass başarılı olmazsa, hata durumunu fırlat (veya None dön)
                    response.raise_for_status() # Hata fırlatmayı garanti et
                    return None

            response.raise_for_status() # Diğer HTTP hata durumlarında istisna fırlat
            return response
        except requests.exceptions.RequestException as e:
            print(f"GET isteği başarısız oldu {url}: {e}")
            return None

    def post(self, url, data=None, headers=None, allow_redirects=True, timeout=30):
        if headers:
            self.session.headers.update(headers)
        if self.cf_cookies:
            cookie_header = "; ".join([f"{name}={value}" for name, value in self.cf_cookies.items()])
            self.session.headers.update({'Cookie': cookie_header})
        self.session.headers.update({'User-Agent': self.user_agent})

        try:
            response = self.session.post(url, data=data, allow_redirects=allow_redirects, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"POST isteği başarısız oldu {url}: {e}")
            return None

request_handler = RequestHandler()
