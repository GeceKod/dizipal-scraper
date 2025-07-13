import re
from requests_handler import request_handler
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import json

class ContentXExtractor:
    def __init__(self):
        self.main_url = "https://contentx.me" # ContentX'in ana URL'i
        self.requires_referer = True #

    def _decrypt_aes(self, passphrase, salt_hex, iv_hex, ciphertext_base64):
        # DiziPalOrijinal.kt'deki decrypt fonksiyonunun Python'a uyarlanmas\u0131
        try:
            salt = bytes.fromhex(salt_hex)
            iv = bytes.fromhex(iv_hex)
            ciphertext = base64.b64decode(ciphertext_base64)

            # PBKDF2 anahtar t\u00FCretme (999 iterasyon, SHA512, 256 bit = 32 byte anahtar)
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                salt=salt,
                iterations=999,
                backend=default_backend()
            )
            key = kdf.derive(passphrase.encode('utf-8'))

            # AES/CBC/PKCS5Padding \u015Fifre \u00E7\u00F6zme
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # PKCS5Padding'i kald\u0131r
            pad_len = padded_data[-1]
            if pad_len < 1 or pad_len > 16: # Padding uzunlu\u011Fu kontrol\u00FC
                 raise ValueError("Invalid padding length")
            decrypted_content = padded_data[:-pad_len]

            return decrypted_content.decode('utf-8')
        except Exception as e:
            print(f"Şifre \u00E7\u00F6zme ba\u015Far\u0131s\u0131z oldu: {e}")
            return None


    async def get_m3u8_link(self, url, referer):
        print(f"Video ba\u011Flant\u0131s\u0131 \u00E7ekiliyor: {url} (Referer: {referer})...")
        ext_ref = referer if referer else ""

        # Ad\u0131m 1: Oynat\u0131c\u0131 sayfas\u0131ndan iExtract de\u011Ferini al
        i_source_resp = request_handler.get(url, headers={"Referer": ext_ref, "User-Agent": request_handler.user_agent})
        if not i_source_resp:
            print(f"iSource al\u0131namad\u0131 {url}")
            return []

        i_source_text = i_source_resp.text
        i_extract_match = re.search(r"window\.openPlayer\('([^']+)'", i_source_text)
        i_extract = i_extract_match.group(1) if i_extract_match else None

        # E\u011Fer i_extract bulunamad\u0131ysa \u015Fifre \u00E7\u00F6zme denemesi yap
        if not i_extract:
            try:
                # Kotlin kodunda 'var obj = { ... }' \u015Feklinde bir JSON aramas\u0131 var
                json_obj_match = re.search(r'var obj = ({.*?});', i_source_text, re.DOTALL)
                if json_obj_match:
                    json_str = json_obj_match.group(1)
                    data = json.loads(json_str)

                    ciphertext = data.get("ciphertext")
                    iv = data.get("iv")
                    salt = data.get("salt")
                    key = data.get("key") # 'key' parametresinin JSON i\u00E7inde oldu\u011Funu varsay\u0131yoruz

                    if ciphertext and iv and salt and key:
                        print("Şifre \u00E7\u00F6zme deneniyor...")
                        decrypted_content = self._decrypt_aes(key, salt, iv, ciphertext)
                        if decrypted_content:
                            print(f"\u00C7\u00F6z\u00FClen i\u00E7erik: {decrypted_content}")
                            # \u00C7\u00F6z\u00FClen i\u00E7erik bir iframe URL'i ise, o URL'i kullan
                            if "http" in decrypted_content:
                                # Yeni URL'den tekrar i_extract almaya \u00E7al\u0131\u015F
                                print(f"Yeni URL'den iExtract al\u0131nmaya \u00E7al\u0131\u015F\u0131l\u0131yor: {decrypted_content}")
                                i_source_resp_new = request_handler.get(decrypted_content, headers={"Referer": ext_ref, "User-Agent": request_handler.user_agent})
                                if i_source_resp_new:
                                    i_source_text = i_source_resp_new.text
                                    i_extract_match = re.search(r"window\.openPlayer\('([^']+)'", i_source_text)
                                    i_extract = i_extract_match.group(1) if i_extract_match else None
                                else:
                                    print("Şifre \u00E7\u00F6z\u00FClen URL al\u0131namad\u0131.")
                                    return []
                            else:
                                print("\u00C7\u00F6z\u00FClen i\u00E7erik bir URL de\u011Fil, daha fazla analiz gerekli.")
                                return []
                        else:
                            print("\u015Eifre \u00E7\u00F6zme ba\u015Far\u0131s\u0131z oldu.")
                            return []
            except json.JSONDecodeError:
                print("Sayfada \u015Fifre \u00E7\u00F6zme i\u00E7in JSON objesi bulunamad\u0131.")
            except Exception as e:
                print(f"\u015Eifre \u00E7\u00F6zme denemesi s\u0131ras\u0131nda hata: {e}")
            
            if not i_extract: # \u015Eifre \u00E7\u00F6zme denemesi sonras\u0131nda hala i_extract yoksa
                print(f"iExtract bulunamad\u0131 {url}. Oynat\u0131c\u0131 verisi farkl\u0131 veya \u015Fifreli olabilir.")
                return []


        # Ad\u0131m 2: ContentX'in source2.php'sinden video kayna\u011F\u0131n\u0131 al
        source2_url = f"{self.main_url}/source2.php?v={i_extract}"
        print(f"Video kayna\u011F\u0131 \u00E7ekiliyor: {source2_url}")
        vid_source_resp = request_handler.get(source2_url, headers={"Referer": ext_ref, "User-Agent": request_handler.user_agent})
        if not vid_source_resp:
            print(f"Video kayna\u011F\u0131 al\u0131namad\u0131 {source2_url}")
            return []

        vid_source_text = vid_source_resp.text
        m3u_link_match = re.search(r'"file":"([^"]+)"', vid_source_text)
        m3u_link = m3u_link_match.group(1).replace("\\", "") if m3u_link_match else None

        if not m3u_link:
            print(f"source2.php yan\u0131t\u0131nda m3u8 ba\u011Flant\u0131s\u0131 bulunamad\u0131 {i_extract}")
            return []

        # Ad\u0131m 3: Dublaj (T\u00FCrk\u00E7e) ba\u011Flant\u0131s\u0131n\u0131 kontrol et
        dublaj_links = []

        if m3u_link:
            dublaj_links.append({"url": m3u_link, "quality": "Orijinal"})

        # Kotlin kodundaki regex: """,([^']+)","Türkçe"""
        dublaj_match = re.search(r',("([^"]+)","Türk\u00E7e")', i_source_text)
        if dublaj_match:
            dublaj_id = dublaj_match.group(2)
            dublaj_source2_url = f"{self.main_url}/source2.php?v={dublaj_id}"
            print(f"Dublaj kayna\u011F\u0131 \u00E7ekiliyor: {dublaj_source2_url}")
            dublaj_vid_source_resp = request_handler.get(dublaj_source2_url, headers={"Referer": ext_ref, "User-Agent": request_handler.user_agent})
            if dublaj_vid_source_resp:
                dublaj_vid_source_text = dublaj_vid_source_resp.text
                dublaj_m3u_link_match = re.search(r'"file":"([^"]+)"', dublaj_vid_source_text)
                dublaj_m3u_link = dublaj_m3u_link_match.group(1).replace("\\", "") if dublaj_m3u_link_match else None
                if dublaj_m3u_link:
                    dublaj_links.append({"url": dublaj_m3u_link, "quality": "T\u00FCrk\u00E7e Dublaj"})

        return dublaj_links
