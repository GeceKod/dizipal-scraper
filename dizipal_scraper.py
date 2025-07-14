# -*- coding: utf-8 -*-
import re
from bs4 import BeautifulSoup
import json
from requests_handler import request_handler # Özel istek yöneticimizi içeri aktar
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64

class DizipalScraper:
    def __init__(self):
        self.main_url = "https://dizipal936.com"
        self.cKey = None
        self.cValue = None
        # Orijinal Kotlin kodundan alınan sabit şifre çözme anahtarı
        self.decryption_key = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"

    def _decrypt_aes(self, salt_hex, iv_hex, ciphertext_base64):
        """DiziPalOrijinal.kt'deki decrypt fonksiyonunun Python'a uyarlanması."""
        try:
            salt = bytes.fromhex(salt_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = base64.b64decode(ciphertext_base64)
            passphrase = self.decryption_key

            # PBKDF2 anahtar türetme (999 iterasyon, SHA512, 256 bit = 32 byte anahtar)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=999,
                backend=default_backend()
            )
            key = kdf.derive(passphrase.encode('utf-8'))

            # AES/CBC/PKCS5Padding şifre çözme
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # PKCS#7 (veya PKCS#5) padding'i kaldır
            pad_len = padded_data[-1]
            # Padding uzunluğunun geçerli bir aralıkta olduğundan emin ol
            if not 1 <= pad_len <= 16:
                raise ValueError("Geçersiz padding uzunluğu.")
            # Padding'in doğru olup olmadığını kontrol et
            if not all(p == pad_len for p in padded_data[-pad_len:]):
                raise ValueError("Geçersiz padding.")
            
            decrypted_content = padded_data[:-pad_len]
            return decrypted_content.decode('utf-8')
        except Exception as e:
            print(f"Şifre çözme başarısız oldu: {e}")
            return None

    async def init_session(self):
        if self.cKey and self.cValue:
            print("Oturum zaten başlatıldı.")
            return True
        print("🔄 Oturum başlatılıyor: çerezler, cKey ve cValue alınıyor...")
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": request_handler.user_agent,
            "Referer": f"{self.main_url}/",
        }
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
            return True
        else:
            print("cKey veya cValue sayfada bulunamadı.")
            return False

    async def get_main_page_content(self, page=1, request_name="Yeni Eklenen Bölümler"):
        """Ana sayfadaki ve kategorilerdeki içerik listelerini çeker."""
        await self.init_session()
        
        headers = {"User-Agent": request_handler.user_agent, "Referer": f"{self.main_url}/"}
        
        if "Yeni Eklenen Bölümler" in request_name:
             response = request_handler.get(self.main_url, headers=headers)
        else:
            # Diğer POST istekleri için ortak mantık (henüz tam implemente edilmedi)
            print(f"'{request_name}' için listeleme mantığı henüz eklenmedi.")
            return []

        if not response:
            print(f"İçerik alınamadı: {request_name}")
            return []

        soup = BeautifulSoup(response.text, 'html.parser')
        home_results = []
        
        # Sadece "Yeni Eklenen Bölümler" için Kotlin'deki seçiciyi kullanıyoruz
        # div.overflow-auto içindeki a etiketleri
        links = soup.select("div.overflow-auto a")
        
        for link_tag in links:
            raw_href = link_tag.get('href')
            img_tag = link_tag.select_first("img")
            if not raw_href or not img_tag:
                continue

            # Kotlin kodundaki link düzeltme mantığı
            # Örn: /bolum/the-boys-1-sezon-1-bolum -> /series/the-boys
            if "/bolum/" in raw_href:
                href = re.sub(r"-[0-9]+x.*$", "", raw_href.replace("/bolum/", "/series/"))
            else:
                href = raw_href
            
            full_url = href if href.startswith('http') else self.main_url + href
            
            # Başlık oluşturma
            title_alt = img_tag.get('alt', '').strip()
            title_text_element = link_tag.select_first("div.text.block div.text-white.text-sm")
            title_text = title_text_element.text.strip() if title_text_element else ""
            
            full_title = f"{title_alt} {title_text}".strip()
            
            home_results.append({"title": full_title, "url": full_url})
            
        return home_results
    
    async def get_player_url(self, episode_url):
        """Verilen bölüm URL'inden şifrelenmiş oynatıcı URL'ini çözer."""
        print(f"Oynatıcı URL'i alınıyor: {episode_url}")
        headers = {"Referer": self.main_url, "User-Agent": request_handler.user_agent}
        resp = request_handler.get(episode_url, headers=headers)
        
        if not resp:
            print(f"Bölüm sayfası alınamadı: {episode_url}")
            return None

        soup = BeautifulSoup(resp.text, 'html.parser')
        hidden_div = soup.select_one("div[data-rm-k]")
        
        if not (hidden_div and hidden_div.text):
            print("Sayfada şifreli veri (div[data-rm-k]) bulunamadı.")
            return None
        
        try:
            json_data = json.loads(hidden_div.text)
            ciphertext = json_data.get("ciphertext")
            iv = json_data.get("iv")
            salt = json_data.get("salt")
            
            if not all([ciphertext, iv, salt]):
                print("JSON veri içinde gerekli anahtarlar (ciphertext, iv, salt) eksik.")
                return None

            decrypted_url = self._decrypt_aes(salt, iv, ciphertext)
            return decrypted_url
        except Exception as e:
            print(f"Şifreli veri işlenirken hata oluştu: {e}")
            return None
