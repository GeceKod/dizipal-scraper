# -*- coding: utf-8 -*-
import re
from bs4 import BeautifulSoup
import json
from requests_handler import request_handler # Özel istek yöneticimizi içeri aktar

class DizipalScraper:
    def __init__(self):
        # DiziPalOrijinal.kt'den ana URL'i alıyoruz
        self.main_url = "https://dizipal936.com" # Güncel Dizipal adresini buraya girin!
        self.cKey = None
        self.cValue = None

    async def init_session(self): # Kotlin'deki suspend fun benzeri asenkron
        if self.cKey and self.cValue:
            print("Oturum zaten başlatıldı.")
            return True

        print("🔄 Oturum başlatılıyor: çerezler, cKey ve cValue alınıyor...")

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": request_handler.user_agent, # Bypass sonrası User-Agent'i kullan
            "Referer": f"{self.main_url}/",
        }

        # Cloudflare ve diğer korumaları otomatik olarak handle etmesi için
        resp = request_handler.get(self.main_url, headers=headers, timeout=120, handle_protection=True)
        if not resp:
            print("Dizipal ana sayfası alınamadı.")
            return False

        soup = BeautifulSoup(resp.text, 'html.parser')
        c_key_input = soup.select_one("input[name=cKey]")
        c_value_input = soup.select_one("input[name=cValue]")

        if c_key_input and c_value_input:
            self.cKey = c_key_input.get('value')
            self.cValue = c_value_input.get('value')
            print(f"cKey: {self.cKey}, cValue: {self.cValue}")
        else:
            print("cKey veya cValue sayfada bulunamadı.")
            return False
        return True

    async def get_main_page_content(self, page=1, request_name="Yeni Eklenen Bölümler", request_data=""):
        await self.init_session() # Oturumu başlattığımızdan emin ol

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
            "User-Agent": request_handler.user_agent, # Bypass sonrası User-Agent'i kullan
            "Referer": f"{self.main_url}/",
            "X-Requested-With": "XMLHttpRequest", # Genellikle AJAX POST istekleri için gereklidir
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        }

        response = None
        if any(k in request_name for k in kanallar_list): # Kanal bazlı listeleme
            post_data.update({"channelId": request_data, "languageId": "2,3,4"})
            response = request_handler.post(f"{self.main_url}/bg/getserielistbychannel", data=post_data, headers=headers)
        elif "Yeni Eklenenler" in request_name: # Yeni eklenen diziler
            post_data.update({"categoryIdsComma[]": request_data, "orderType": "date_asc"})
            response = request_handler.post(f"{self.main_url}/bg/findseries", data=post_data, headers=headers)
        elif "Yeni Eklenen Bölümler" in request_name: # Ana sayfadaki bölümler (GET isteği)
            response = request_handler.get(self.main_url, headers=headers) # Ana sayfa HTML'ini çek
        elif "Yeni Filmler" in request_name: # Yeni eklenen filmler
            post_data.update({"categoryIdsComma[]": request_data, "orderType": "date_desc"})
            response = request_handler.post(f"{self.main_url}/bg/findmovies", data=post_data, headers=headers)
        else: # Varsayılan (IMDb puanına göre diziler vb.)
            post_data.update({"categoryIdsComma[]": request_data, "orderType": "imdb_desc"})
            response = request_handler.post(f"{self.main_url}/bg/findseries", data=post_data, headers=headers)

        if not response:
            print(f"İçerik alınamadı: {request_name}")
            return []

        body_text = response.text
        html_fragment = ""
        try:
            # Yanıt JSON ise 'data.html' alanını çek
            json_data = json.loads(body_text)
            if 'data' in json_data and 'html' in json_data['data']:
                html_fragment = json_data['data']['html']
            else:
                html_fragment = body_text # JSON ama 'data.html' yoksa tüm body'yi kullan
        except json.JSONDecodeError:
            html_fragment = body_text # JSON değilse doğrudan HTML olarak işleme al

        soup = BeautifulSoup(html_fragment, 'html.parser')

        home_results = []
        if "Yeni Eklenen Bölümler" in request_name:
            # Kotlin kodundaki seçici
            links = soup.select("div.overflow-auto a")
        else:
            # Genel film/dizi listeleri için seçici
            links = soup.select("div.prm-borderb a") # Dizipal HTML yapısına göre ayarlanmalı

        for link_tag in links:
            href = link_tag.get('href')
            title = link_tag.get_text(strip=True)
            if href:
                # Bağlantı tam URL değilse ana URL ile birleştir
                full_url = href if href.startswith('http') else self.main_url + href
                home_results.append({"title": title, "url": full_url})

        return home_results
