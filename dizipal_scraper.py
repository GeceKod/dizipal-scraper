import re
from bs4 import BeautifulSoup
import json
from requests_handler import request_handler # Özel istek yöneticimizi içeri aktar

class DizipalScraper:
    def __init__(self):
        # DiziPalOrijinal.kt'den ana URL'i alıyoruz
        self.main_url = "https://dizipal936.com" # G\u00FCncel Dizipal adresini buraya girin!
        self.cKey = None
        self.cValue = None

    async def init_session(self): # Kotlin'deki suspend fun benzeri asenkron
        if self.cKey and self.cValue:
            print("Oturum zaten ba\u015Flat\u0131ld\u0131.")
            return True

        print("🔄 Oturum ba\u015F\u013lat\u0131l\u0131yor: \u00E7erezler, cKey ve cValue al\u0131n\u0131yor...")

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": request_handler.user_agent, # Bypass sonras\u0131 User-Agent'i kullan
            "Referer": f"{self.main_url}/",
        }

        # Cloudflare ve di\u011Fer korumalar\u0131 otomatik olarak handle etmesi i\u00E7in
        resp = request_handler.get(self.main_url, headers=headers, timeout=120, handle_protection=True)
        if not resp:
            print("Dizipal ana sayfas\u0131 al\u0131namad\u0131.")
            return False

        soup = BeautifulSoup(resp.text, 'html.parser')
        c_key_input = soup.select_one("input[name=cKey]")
        c_value_input = soup.select_one("input[name=cValue]")

        if c_key_input and c_value_input:
            self.cKey = c_key_input.get('value')
            self.cValue = c_value_input.get('value')
            print(f"cKey: {self.cKey}, cValue: {self.cValue}")
        else:
            print("cKey veya cValue sayfada bulunamad\u0131.")
            return False
        return True

    async def get_main_page_content(self, page=1, request_name="Yeni Eklenen Bölümler", request_data=""):
        await self.init_session() # Oturumu ba\u015Flatt\u0131\u011F\u0131m\u0131zdan emin ol

        kanallar_list = [
            "Exxen Diziler", "Disney+ Dizileri", "Netflix Dizileri",
            "Amazon Dizileri", "Apple TV+ Dizileri", "Max Dizileri",
            "Hulu Dizileri", "TOD Dizileri", "Tabii Dizileri"
        ]

        post_data = {
            "cKey": self.cKey,
            "cValue": self.cValue,
            "currentPage": str(page),
            "releaseYearStart": "1923",
            "releaseYearEnd": "2025"
        }
        headers = {
            "User-Agent": request_handler.user_agent, # Bypass sonras\u0131 User-Agent'i kullan
            "Referer": f"{self.main_url}/",
            "X-Requested-With": "XMLHttpRequest", # Genellikle AJAX POST istekleri i\u00E7in gereklidir
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        }

        response = None
        if any(k in request_name for k in kanallar_list): # Kanal bazl\u0131 listeleme
            post_data.update({"channelId": request_data, "languageId": "2,3,4"})
            response = request_handler.post(f"{self.main_url}/bg/getserielistbychannel", data=post_data, headers=headers)
        elif "Yeni Eklenenler" in request_name: # Yeni eklenen diziler
            post_data.update({"categoryIdsComma[]": request_data, "orderType": "date_asc"})
            response = request_handler.post(f"{self.main_url}/bg/findseries", data=post_data, headers=headers)
        elif "Yeni Eklenen Bölümler" in request_name: # Ana sayfadaki b\u00F6l\u00FCmler (GET iste\u011Fi)
            response = request_handler.get(self.main_url, headers=headers) # Ana sayfa HTML'ini \u00E7ek
        elif "Yeni Filmler" in request_name: # Yeni eklenen filmler
            post_data.update({"categoryIdsComma[]": request_data, "orderType": "date_desc"})
            response = request_handler.post(f"{self.main_url}/bg/findmovies", data=post_data, headers=headers)
        else: # Varsay\u0131lan (IMDb puan\u0131na g\u00F6re diziler vb.)
            post_data.update({"categoryIdsComma[]": request_data, "orderType": "imdb_desc"})
            response = request_handler.post(f"{self.main_url}/bg/findseries", data=post_data, headers=headers)

        if not response:
            print(f"İ\u00E7erik al\u0131namad\u0131: {request_name}")
            return []

        body_text = response.text
        html_fragment = ""
        try:
            # Yan\u0131t JSON ise 'data.html' alan\u0131n\u0131 \u00E7ek
            json_data = json.loads(body_text)
            if 'data' in json_data and 'html' in json_data['data']:
                html_fragment = json_data['data']['html']
            else:
                html_fragment = body_text # JSON ama 'data.html' yoksa t\u00FCm body'yi kullan
        except json.JSONDecodeError:
            html_fragment = body_text # JSON de\u011Filse do\u011Frudan HTML olarak i\u015Fleme al

        soup = BeautifulSoup(html_fragment, 'html.parser')

        home_results = []
        if "Yeni Eklenen Bölümler" in request_name:
            # Kotlin kodundaki se\u00E7ici
            links = soup.select("div.overflow-auto a")
        else:
            # Genel film/dizi listeleri i\u00E7in se\u00E7ici
            links = soup.select("div.prm-borderb a") # Dizipal HTML yap\u0131s\u0131na g\u00F6re ayarlanmal\u0131

        for link_tag in links:
            href = link_tag.get('href')
            title = link_tag.get_text(strip=True)
            if href:
                # Ba\u011Flant\u0131 tam URL de\u011Filse ana URL ile birle\u015Ftir
                full_url = href if href.startswith('http') else self.main_url + href
                home_results.append({"title": title, "url": full_url})

        return home_results
