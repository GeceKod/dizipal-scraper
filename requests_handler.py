import requests
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options as ChromeOptions
import time # Tekrar deneme arasındaki bekleme için eklendi
import re
from urllib.parse import unquote
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By

class RequestHandler:
    def __init__(self):
        self.session = requests.Session()
        self.cf_cookies = {}
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"

    def _bypass_cloudflare(self, url):
        print(f"Cloudflare aşıma girişimi: {url} (Selenium ile)...")
        options = ChromeOptions()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(f"user-agent={self.user_agent}")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--start-maximized")
        options.add_argument("--disable-blink-features=AutomationControlled")
        options.add_experimental_option("excludeSwitches", ["enable-automation"])
        options.add_experimental_option('useAutomationExtension', False)
        
        driver = None
        try:
            driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
            
            driver.execute_cdp_cmd("Page.addScriptToEvaluateOnNewDocument", {
                "source": """
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => false
                    });
                """
            })

            driver.get(url)
            
            max_wait_time = 30
            poll_interval = 2
            found_cf_cookies = False
            start_time = time.time()

            while time.time() - start_time < max_wait_time:
                current_cookies = driver.get_cookies()
                if any(c['name'] == 'cf_clearance' or c['name'] == '__cf_bm' for c in current_cookies):
                    self.cf_cookies = {cookie['name']: cookie['value'] for cookie in current_cookies}
                    found_cf_cookies = True
                    break
                time.sleep(poll_interval)

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
                driver.quit()

    def _bypass_ddos_guard(self, url):
        print(f"DDoS-Guard aşıma girişimi: {url}...")
        try:
            check_js_url = "https://check.ddos-guard.net/check.js"
            js_response = self.session.get(check_js_url, timeout=10)
            js_response.raise_for_status()
            
            match = re.search(r"'(.*?)'", js_response.text)
            if match:
                bypass_path = match.group(1)
                bypass_url = f"https://{requests.utils.urlparse(url).netloc}{bypass_path}"
                
                print(f"DDoS-Guard bypass URL'si: {bypass_url}")
                bypass_response = self.session.get(bypass_url, timeout=10)
                bypass_response.raise_for_status()

                print(f"DDoS-Guard aşma başarılı. Çerezler alındı: {self.session.cookies.get_dict()}")
                return True
            else:
                print("DDoS-Guard bypass path'i bulunamadı.")
                return False
        except Exception as e:
            print(f"DDoS-Guard aşma başarısız oldu: {e}")
            return False

    def get(self, url, headers=None, allow_redirects=True, timeout=30, handle_protection=False):
        # --- YENİ EKLENEN KISIM BAŞLANGICI ---
        max_retries = 3
        retry_delay = 5
        for attempt in range(max_retries + 1): # 1 ilk deneme + 3 tekrar deneme
        # --- YENİ EKLENEN KISIM SONU ---
            try:
                if headers:
                    self.session.headers.update(headers)
                if self.cf_cookies:
                    cookie_header = "; ".join([f"{name}={value}" for name, value in self.cf_cookies.items()])
                    self.session.headers.update({'Cookie': cookie_header})
                self.session.headers.update({'User-Agent': self.user_agent})

                response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)

                if handle_protection and (response.status_code == 403 or response.status_code == 503):
                    print(f"Koruma tespit edildi {url}. Aşma deneniyor...")
                    bypass_successful = False

                    if self._bypass_cloudflare(url):
                        print(f"Cloudflare aşma başarılı: {url}. Orijinal istek tekrarlanıyor...")
                        if self.cf_cookies:
                            cookie_header = "; ".join([f"{name}={value}" for name, value in self.cf_cookies.items()])
                            self.session.headers.update({'Cookie': cookie_header})
                        response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)
                        bypass_successful = True
                    else:
                        print(f"Cloudflare aşma başarısız oldu: {url}.")

                    if not bypass_successful:
                        if self._bypass_ddos_guard(url):
                            print(f"DDoS-Guard aşma başarılı: {url}. Orijinal istek tekrarlanıyor...")
                            response = self.session.get(url, allow_redirects=allow_redirects, timeout=timeout)
                            bypass_successful = True
                        else:
                            print(f"DDoS-Guard aşma başarısız oldu: {url}.")

                    if not bypass_successful:
                        print(f"Hiçbir koruma aşma girişimi başarılı olamadı: {url}.")
                        response.raise_for_status()
                        return None

                response.raise_for_status()
                return response # İstek başarılı olursa döngüden çık ve yanıtı döndür

            # --- YENİ EKLENEN KISIM BAŞLANGICI ---
            except requests.exceptions.RequestException as e:
                print(f"GET isteği denemesi {attempt + 1}/{max_retries + 1} başarısız oldu: {url}")
                if attempt < max_retries:
                    print(f"Hata: {e}. {retry_delay} saniye beklenip tekrar denenecek...")
                    time.sleep(retry_delay)
                else:
                    print("Maksimum deneme sayısına ulaşıldı. İstek kalıcı olarak başarısız oldu.")
                    return None
            # --- YENİ EKLENEN KISIM SONU ---
        return None


    def post(self, url, data=None, headers=None, allow_redirects=True, timeout=30):
        # --- YENİ EKLENEN KISIM BAŞLANGICI ---
        max_retries = 3
        retry_delay = 5
        for attempt in range(max_retries + 1):
        # --- YENİ EKLENEN KISIM SONU ---
            try:
                if headers:
                    self.session.headers.update(headers)
                if self.cf_cookies:
                    cookie_header = "; ".join([f"{name}={value}" for name, value in self.cf_cookies.items()])
                    self.session.headers.update({'Cookie': cookie_header})
                self.session.headers.update({'User-Agent': self.user_agent})

                response = self.session.post(url, data=data, allow_redirects=allow_redirects, timeout=timeout)
                response.raise_for_status()
                return response # İstek başarılı olursa döngüden çık ve yanıtı döndür
            
            # --- YENİ EKLENEN KISIM BAŞLANGICI ---
            except requests.exceptions.RequestException as e:
                print(f"POST isteği denemesi {attempt + 1}/{max_retries + 1} başarısız oldu: {url}")
                if attempt < max_retries:
                    print(f"Hata: {e}. {retry_delay} saniye beklenip tekrar denenecek...")
                    time.sleep(retry_delay)
                else:
                    print("Maksimum deneme sayısına ulaşıldı. İstek kalıcı olarak başarısız oldu.")
                    return None
            # --- YENİ EKLENEN KISIM SONU ---
        return None


request_handler = RequestHandler()
