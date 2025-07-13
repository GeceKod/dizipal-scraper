import re
from bs4 import BeautifulSoup
import json
from requests_handler import request_handler # Özel istek yöneticimizi içeri aktar

# Kriptografi kütüphanesinden gerekli importlar
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

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
        resp = request_handler.get(self.main_url, headers=headers, handle_protection=True)
        if not resp:
            print("Dizipal ana sayfası alınamadı.")
            return False

        # Kotlin DiziPalOrijinal.kt'den cKey ve cValue çekme mantığı
        # Bu kısım HTML yapısına göre değişebilir, regex ile yakalamaya çalışıyoruz
        match_ckey = re.search(r"var cKey = '(.*?)';", resp.text)
        match_cvalue = re.search(r"var cValue = '(.*?)';", resp.text)

        if match_ckey and match_cvalue:
            self.cKey = match_ckey.group(1)
            self.cValue = match_cvalue.group(1)
            print(f"cKey: {self.cKey}, cValue: {self.cValue}")
            return True
        else:
            print("Dizipal oturumu başlatılamadı. cKey veya cValue bulunamadı.")
            return False

    # Kotlin'deki decrypt fonksiyonunun Python karşılığı
    def _decrypt_player_data(self, passphrase, salt_hex, iv_hex, ciphertext_base64):
        try:
            salt = bytes.fromhex(salt_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = base64.b64decode(ciphertext_base64)

            # PBKDF2WithHmacSHA512 anahtar türetme
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(), # Kotlin'deki gibi SHA512
                length=32, # AES-256 için 256 bit = 32 byte
                salt=salt,
                iterations=999, # Kotlin'deki gibi 999 iterasyon
                backend=default_backend()
            )
            key = kdf.derive(passphrase.encode('utf-8'))

            # AES/CBC/PKCS5Padding ile şifre çözme
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # PKCS5 dolgusunu kaldırma
            padding_length = padded_data[-1]
            if padding_length > len(padded_data): # Geçersiz dolgu kontrolü
                raise ValueError("Geçersiz dolgu boyutu")
            decrypted_data = padded_data[:-padding_length]

            return decrypted_data.decode('utf-8')
        except Exception as e:
            print(f"Şifre çözme başarısız: {e}")
            return None

    # Bölüm sayfasından oynatıcı URL'sini çekme ve çözme fonksiyonu
    async def get_episode_player_url(self, episode_url):
        print(f"Oynatıcı URL'i alınıyor: {episode_url}")
        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": request_handler.user_agent,
            "Referer": f"{self.main_url}/",
        }

        # Bölüm sayfasını çek
        response = request_handler.get(episode_url, headers=headers, handle_protection=True)
        if not response:
            print(f"Bölüm sayfası alınamadı: {episode_url}")
            return None

        soup = BeautifulSoup(response.text, 'html.parser')

        # Oynatıcı verisini içeren script etiketini bulmaya çalış
        # Bu kısım Dizipal'ın HTML yapısına göre değişebilir.
        # Genellikle 'player_data' veya benzeri bir JS değişkeni içinde JSON olur.
        player_data_script = soup.find('script', string=re.compile(r'var player_data = {.*};'))
        
        ciphertext = None
        iv = None
        salt = None

        if player_data_script:
            print("Player data script etiketi bulundu.")
            # Script içeriğinden JSON'ı regex ile ayıkla
            match = re.search(r'var player_data = ({.*});', player_data_script.string)
            if match:
                player_json_str = match.group(1)
                try:
                    player_data = json.loads(player_json_str)
                    ciphertext = player_data.get('ciphertext')
                    iv = player_data.get('iv')
                    salt = player_data.get('salt')
                    if not (ciphertext and iv and salt):
                        print("Player data JSON'unda ciphertext, iv veya salt eksik.")
                        return None
                except json.JSONDecodeError as e:
                    print(f"Player data JSON ayrıştırma hatası: {e}")
                    return None
            else:
                print("Player data script içeriğinde regex eşleşmesi bulunamadı.")
                return None
        else:
            # Eğer script etiketi bulunamazsa, belki veri bir div'in data niteliklerindedir
            # Örnek: <div id="player-data" data-ciphertext="..." data-iv="..." data-salt="..."></div>
            player_data_div = soup.find('div', id='player-data') # veya class gibi başka bir seçici
            if player_data_div and player_data_div.has_attr('data-ciphertext'):
                print("Player data veri niteliklerinde bulundu.")
                ciphertext = player_data_div['data-ciphertext']
                iv = player_data_div['data-iv']
                salt = player_data_div['data-salt']
            else:
                print("Oynatıcı verisi script etiketinde veya veri niteliklerinde bulunamadı.")
                return None
        
        # cKey zaten init_session'da alınmış olmalı
        if not self.cKey:
            print("cKey oturumdan alınamadı. Şifre çözme yapılamaz.")
            return None

        # Oynatıcı URL'sini şifre çöz
        decrypted_url = self._decrypt_player_data(self.cKey, salt, iv, ciphertext)
        if decrypted_url:
            # Kotlin'deki fixUrlNull mantığı, burada basitçe trimleme ve kontrol yeterli
            print(f"Çözülmüş oynatıcı URL'i: {decrypted_url}")
            return decrypted_url.strip() # Boşlukları temizle
        else:
            print("Oynatıcı URL'i çözülemedi.")
            return None

    async def get_home_content(self, request_name):
        print(f"--- {request_name} ---")
        # DizipalOrijinal.kt'deki getPage fonksiyonuna benzer mantık
        page_url = f"{self.main_url}/index.php"
        params = {"s": ""} # Varsayılan olarak boş arama

        if request_name == "Yeni Eklenen Bölümler":
            params["s"] = "son-eklenen-bolumler"
        elif request_name == "Yeni Eklenen Filmler":
            params["s"] = "son-eklenen-filmler"
        # Diğer kategoriler buraya eklenebilir

        headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "User-Agent": request_handler.user_agent,
            "Referer": f"{self.main_url}/",
        }

        response = request_handler.get(page_url, headers=headers, params=params, handle_protection=True)
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

        for link in links:
            title = link.get_text(strip=True)
            href = link.get('href')
            if title and href:
                # Absolute URL'ye dönüştür
                if not href.startswith('http'):
                    href = self.main_url + href
                home_results.append({'title': title, 'url': href})
        
        # Burada her bir bölüm için oynatıcı URL'sini bulma mantığını ekliyoruz
        processed_results = []
        for item in home_results:
            print(f"İşleniyor: {item['title']} - {item['url']}")
            player_url = await self.get_episode_player_url(item['url'])
            if player_url:
                processed_results.append({'title': item['title'], 'url': player_url})
            else:
                print(f"Oynatıcı iframe'i veya doğrudan oynatıcı URL'i bulunamadı {item['url']}")
        
        return processed_results
