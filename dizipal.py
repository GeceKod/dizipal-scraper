import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
import re
import json
from playwright.sync_api import sync_playwright
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
import base64
import hmac
import hashlib

# Proxy ayarları
PROXY = {
    "server": "socks5://45.89.28.226:12915",
}

# Başlık ayarları
HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0",
}

# Şifre çözme fonksiyonu
def decrypt(passphrase, salt_hex, iv_hex, ciphertext_base64):
    try:
        salt = bytes.fromhex(salt_hex)
        iv = bytes.fromhex(iv_hex)
        ciphertext = base64.b64decode(ciphertext_base64)
        key = PBKDF2(passphrase, salt, dkLen=32, count=999, hmac_hash_module=hashlib.sha512)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = cipher.decrypt(ciphertext)
        padding_len = plaintext[-1]
        plaintext = plaintext[:-padding_len]
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f"Şifre çözme hatası: {e}")
        raise

# Base ExtractorApi sınıfı
class ExtractorApi:
    def get_url(self, url, referer=None, subtitle_callback=None, callback=None):
        raise NotImplementedError

# ContentX Extractor sınıfı
class ContentX(ExtractorApi):
    name = "ContentX"
    main_url = "https://contentx.me"
    requires_reスティ

    def get_url(self, url, referer=None, subtitle_callback=None, callback=None):
        headers = HEADERS.copy()
        headers["Referer"] = referer if referer else url
        try:
            with sync_playwright() as p:
                browser = p.firefox.launch(headless=True, proxy=PROXY)
                context = browser.new_context(user_agent=HEADERS["User-Agent"])
                page = context.new_page()
                page.goto(url)
                page.wait_for_load_state("networkidle")
                i_source = page.content()

                # Hata ayıklama için iframe içeriğini kaydet
                video_param = parse_qs(urlparse(url).query).get('v', [None])[0]
                filename = f"iframe_debug_{video_param or 'unknown'}.html"
                with open(filename, "w", encoding="utf-8") as f:
                    f.write(i_source)
                print(f"Iframe içeriği '{filename}' dosyasına kaydedildi.")

                # Altyazıları çıkarma
                sub_urls = set()
                altyazilar = []
                for match in re.finditer(r'"file":"([^"]+\.vtt[^"]*)","label":"([^"]+)"', i_source):
                    sub_url = match.group(1).replace("\\", "")
                    sub_lang = match.group(2).replace("\\u0131", "ı").replace("\\u0130", "İ").replace("\\u00fc", "ü").replace("\\u00e7", "ç")
                    if sub_url not in sub_urls:
                        sub_urls.add(sub_url)
                        altyazilar.append({"dil": sub_lang, "url": urljoin(self.main_url, sub_url)})
                        if subtitle_callback:
                            subtitle_callback(altyazilar[-1])

                # Video linkini çıkarma
                linkler = []
                video_file_match = re.search(r'"file":"((?:(?!\\.vtt)[^"])+\\.(?:m3u8|mp4)[^"]*)"', i_source)
                if video_file_match:
                    m3u_link = video_file_match.group(1).replace("\\", "")
                    linkler.append({"kaynak": "ContentX (Direct Video)", "isim": "ContentX Video", "url": m3u_link, "tur": "m3u8"})
                    if callback:
                        callback(linkler[-1])
                    browser.close()
                    return {"linkler": linkler, "altyazilar": altyazilar}

                open_player_match = re.search(r"window\.openPlayer\('([^']+)'\)", i_source)
                if open_player_match:
                    i_extract_val = open_player_match.group(1)
                    base_iframe_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
                    source_url = f"{base_iframe_url}/source2.php?v={i_extract_val}"
                    print(f"ContentX: source2.php'ye istek gönderiliyor: {source_url}")

                    page.goto(source_url)
                    page.wait_for_load_state("networkidle")
                    vid_source = page.content()

                    # source2.php içeriğini kaydet
                    with open("source2_debug.html", "w", encoding="utf-8") as f:
                        f.write(vid_source)
                    print("source2.php içeriği 'source2_debug.html' dosyasına kaydedildi.")

                    vid_extract_match = re.search(r'"file":"((?:(?!\\.vtt)[^"])+\\.(?:m3u8|mp4)[^"]*)"', vid_source)
                    if vid_extract_match:
                        m3u_link = vid_extract_match.group(1).replace("\\", "")
                        linkler.append({"kaynak": "ContentX (Source2 Video)", "isim": "ContentX Video", "url": m3u_link, "tur": "m3u8"})
                        if callback:
                            callback(linkler[-1])
                        browser.close()
                        return {"linkler": linkler, "altyazilar": altyazilar}

                print(f"ContentX Hatası: Video linki bulunamadı. Sayfa içeriği değişmiş olabilir: {url}")
                browser.close()
                return {"linkler": [], "altyazilar": altyazilar}

        except Exception as e:
            print(f"ContentX çıkarma başarısız: {e}")
            return {"linkler": [], "altyazilar": []}

# DiziPalOrijinal sınıfı
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
        HEADERS['Referer'] = self.main_url + "/"

    def init_session(self):
        if self.session_cookies and self.c_key and self.c_value:
            return
        print("Oturum başlatılıyor: çerezler, cKey ve cValue alınıyor")
        try:
            with sync_playwright() as p:
                browser = p.firefox.launch(headless=True, proxy=PROXY)
                context = browser.new_context(user_agent=HEADERS["User-Agent"])
                page = context.new_page()
                page.goto(self.main_url)
                page.wait_for_load_state("networkidle")
                self.session_cookies = {cookie["name"]: cookie["value"] for cookie in page.context.cookies()}
                soup = BeautifulSoup(page.content(), 'html.parser')
                self.c_key = soup.select_one("input[name=cKey]")['value'] if soup.select_one("input[name=cKey]") else None
                self.c_value = soup.select_one("input[name=cValue]")['value'] if soup.select_one("input[name=cValue]") else None
                print(f"cKey: {self.c_key}, cValue: {self.c_value}")
                if not self.c_key or not self.c_value:
                    raise ValueError("cKey veya cValue alınamadı")
                browser.close()
        except Exception as e:
            print(f"Oturum başlatma başarısız: {e}")
            raise

    def load_links(self, data, is_casting, subtitle_callback, callback):
        self.init_session()
        try:
            with sync_playwright() as p:
                browser = p.firefox.launch(headless=True, proxy=PROXY)
                context = browser.new_context(user_agent=HEADERS["User-Agent"])
                for name, value in self.session_cookies.items():
                    context.add_cookies([{"name": name, "value": value, "url": self.main_url}])
                page = context.new_page()
                page.goto(data)
                page.wait_for_load_state("networkidle")
                soup = BeautifulSoup(page.content(), 'html.parser')
                hidden_json = soup.select_one("div[data-rm-k]").text
                obj = json.loads(hidden_json)

                # Şifre çözme parametreleri
                ciphertext = obj['ciphertext']
                iv = obj['iv']
                salt = obj['salt']
                passphrase = "3hPn4uCjTVtfYWcjIcoJQ4cL1WWk1qxXI39egLYOmNv6IblA7eKJz68uU3eLzux1biZLCms0quEjTYniGv5z1JcKbNIsDQFSeIZOBZJz4is6pD7UyWDggWWzTLBQbHcQFpBQdClnuQaMNUHtLHTpzCvZy33p6I7wFBvL4fnXBYH84aUIyWGTRvM2G5cfoNf4705tO2kv"

                # Şifre çözme
                decrypted_content = decrypt(passphrase, salt, iv, ciphertext)
                iframe_url = urljoin(self.main_url, decrypted_content) if not decrypted_content.startswith("http") else decrypted_content
                print(f"Çözülen iframe URL: {iframe_url}")

                # Extractor ile linkleri çıkarma
                for extractor in self.extractors:
                    result = extractor.get_url(iframe_url, referer=data, subtitle_callback=subtitle_callback, callback=callback)
                    if result["linkler"] or result["altyazilar"]:
                        browser.close()
                        return True
                browser.close()
                return False

        except Exception as e:
            print(f"Link çıkarma hatası: {e}")
            return False

    def calistir(self):
        """Ana sayfadan dizileri kazı ve JSON olarak kaydet."""
        self.init_session()
        url = f"{self.main_url}/yabanci-dizi-izle"
        try:
            with sync_playwright() as p:
                browser = p.firefox.launch(headless=True, proxy=PROXY)
                context = browser.new_context(user_agent=HEADERS["User-Agent"])
                for name, value in self.session_cookies.items():
                    context.add_cookies([{"name": name, "value": value, "url": self.main_url}])
                page = context.new_page()
                page.goto(url)
                page.wait_for_load_state("networkidle")
                soup = BeautifulSoup(page.content(), 'html.parser')
                series_divs = soup.select("div.prm-borderb")
                print(f"Ana sayfada bulunan öğe sayısı: {len(series_divs)}")
                all_data = []
                processed_series_urls = set()

                for item in series_divs:
                    try:
                        a_tag = item.select_one("a")
                        if not a_tag:
                            continue
                        raw_href = a_tag.get("href", "")
                        series_href = ""
                        if "/bolum/" in raw_href:
                            parts = raw_href.split('/')[2].split('-')
                            if 'sezon' in parts and 'bolum' in parts:
                                sezon_index = parts.index('sezon')
                                series_name = '-'.join(parts[:sezon_index-1])
                                series_href = f"/series/{series_name}"
                            else:
                                series_href = "/series/" + '-'.join(raw_href.split('/')[2].split('-')[:-4])
                        elif "/series/" in raw_href:
                            series_href = raw_href
                        else:
                            continue

                        series_url = urljoin(self.main_url, series_href)
                        if series_url in processed_series_urls:
                            continue
                        processed_series_urls.add(series_url)

                        title = item.select_one("img").get("alt", "Bilinmeyen Başlık")

                        series_data = {"baslik": title, "url": series_url, "bolumler": []}
                        print(f"\nİşleniyor: {title} ({series_url})")

                        page.goto(series_url)
                        page.wait_for_load_state("networkidle")
                        series_soup = BeautifulSoup(page.content(), 'html.parser')
                        episode_links = series_soup.select("a.text.block[data-dizipal-pageloader='true']")
                        print(f"  > {len(episode_links)} bölüm bulundu.")

                        for ep_link in episode_links:
                            episode_url = urljoin(self.main_url, ep_link['href'])
                            video_data = self.load_links(episode_url, False, lambda subtitle: print(f"Altyazı: {subtitle}"), lambda link: print(f"Video Linki: {link}"))
                            series_data["bolumler"].append({"url": episode_url, "video_bilgisi": video_data})

                        all_data.append(series_data)

                    except Exception as e:
                        print(f"Bir seri işlenirken hata oluştu: {e}")
                        continue

                browser.close()
                with open("dizipal_sonuclar.json", "w", encoding="utf-8") as f:
                    json.dump(all_data, f, ensure_ascii=False, indent=4)
                print("\nTüm veriler 'dizipal_sonuclar.json' dosyasına kaydedildi.")

        except Exception as e:
            print(f"Ana sayfa kazıma hatası: {e}")

# Örnek kullanım
if __name__ == "__main__":
    dizipal = DiziPalOrijinal()
    dizipal.calistir()
