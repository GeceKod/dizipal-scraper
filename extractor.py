import re
from requests_handler import request_handler
import json
from urllib.parse import urlparse # Dinamik URL oluşturmak için eklendi

class ContentXExtractor:
    def __init__(self):
        # Artık sabit bir ana URL'e ihtiyacımız yok, dinamik olarak alacağız.
        self.requires_referer = True

    async def get_m3u8_link(self, url, referer):
        """ContentX ve türevlerinden M3U8 video linkini çeker."""
        print(f"  -> ContentX Extractor çalışıyor: {url}")
        
        # Gelen URL'den ana alan adını dinamik olarak al (örn: https://four.dplayer82.site)
        parsed_url = urlparse(url)
        main_url = f"{parsed_url.scheme}://{parsed_url.netloc}"

        ext_ref = referer if referer else ""
        headers = {"Referer": ext_ref, "User-Agent": request_handler.user_agent}

        # Adım 1: Oynatıcı sayfasından iExtract değerini al
        i_source_resp = request_handler.get(url, headers=headers)
        if not i_source_resp:
            print(f"     ContentX oynatıcı sayfası alınamadı: {url}")
            return []
        
        i_source_text = i_source_resp.text
        i_extract_match = re.search(r"window\.openPlayer\('([^']+)'", i_source_text)
        if not i_extract_match:
            print(f"     ContentX sayfasında 'iExtract' anahtarı bulunamadı.")
            return []
        i_extract = i_extract_match.group(1)

        # Adım 2: source2.php'den video kaynağını al
        source2_url = f"{main_url}/source2.php?v={i_extract}"
        print(f"     Video kaynağı çekiliyor: {source2_url}")
        vid_source_resp = request_handler.get(source2_url, headers=headers)
        if not vid_source_resp:
            print(f"     Video kaynağı alınamadı: {source2_url}")
            return []

        vid_source_text = vid_source_resp.text
        m3u_link_match = re.search(r'"file":"([^"]+)"', vid_source_text)
        if not m3u_link_match:
            print(f"     source2.php yanıtında m3u8 bağlantısı bulunamadı.")
            return []
            
        m3u_link = m3u_link_match.group(1).replace("\\", "")
        
        links = [{"url": m3u_link, "quality": "Orijinal"}]

        # Adım 3: Dublaj (Türkçe) bağlantısını kontrol et
        dublaj_match = re.search(r',("([^"]+)","Türkçe")', i_source_text)
        if dublaj_match:
            try:
                dublaj_id = json.loads(dublaj_match.group(1))
                dublaj_source2_url = f"{main_url}/source2.php?v={dublaj_id}"
                print(f"     Dublaj kaynağı çekiliyor: {dublaj_source2_url}")
                dublaj_vid_source_resp = request_handler.get(dublaj_source2_url, headers=headers)
                if dublaj_vid_source_resp:
                    dublaj_vid_source_text = dublaj_vid_source_resp.text
                    dublaj_m3u_link_match = re.search(r'"file":"([^"]+)"', dublaj_vid_source_text)
                    if dublaj_m3u_link_match:
                        dublaj_m3u_link = dublaj_m3u_link_match.group(1).replace("\\", "")
                        links.append({"url": dublaj_m3u_link, "quality": "Türkçe Dublaj"})
            except Exception as e:
                print(f"     Dublaj linki işlenirken hata: {e}")

        return links
