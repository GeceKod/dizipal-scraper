import requests
import json
import re
import time
import random
import logging
from bs4 import BeautifulSoup
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import unpad
import base64
import cloudscraper

# Log ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dizipal_parser.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Rastgele User-Agent listesi
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1'
]

def create_scraper():
    """Cloudflare bypass özellikli scraper oluşturur"""
    return cloudscraper.create_scraper(browser={
        'browser': 'chrome',
        'platform': 'windows',
        'desktop': True,
        'mobile': False
    }, interpreter='nodejs')

def get_cookies_and_cKey_cValue():
    """cKey ve cValue değerlerini alır"""
    logger.info("Oturum başlatılıyor: çerezler, cKey ve cValue alınıyor")
    
    url = "https://dizipal935.com/"
    max_retries = 3
    retry_delay = 5
    
    for attempt in range(max_retries):
        try:
            scraper = create_scraper()
            response = scraper.get(url, timeout=15)
            response.raise_for_status()
            
            # Cookie kontrolü
            if 'cf_clearance' not in scraper.cookies.get_dict():
                raise ValueError("Cloudflare clearance cookie alınamadı")
                
            soup = BeautifulSoup(response.text, 'html.parser')
            script_tags = soup.find_all('script')
            
            cKey = None
            cValue = None
            
            for script in script_tags:
                if script.string:
                    cKey_match = re.search(r'cKey\s*=\s*"([a-f0-9]+)"', script.string)
                    cValue_match = re.search(r'cValue\s*=\s*"([^"]+)"', script.string)
                    
                    if cKey_match and cValue_match:
                        cKey = cKey_match.group(1)
                        cValue = cValue_match.group(1)
                        break
            
            if cKey and cValue:
                logger.info(f"cKey: {cKey}, cValue: {cValue}")
                return scraper.cookies.get_dict(), cKey, cValue
            
            raise ValueError("cKey veya cValue bulunamadı")
        
        except Exception as e:
            logger.error(f"Hata (Deneme {attempt+1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                sleep_time = retry_delay * (attempt + 1) + random.uniform(1, 3)
                logger.info(f"{sleep_time:.1f} saniye sonra yeniden denenecek...")
                time.sleep(sleep_time)
    
    raise RuntimeError("cKey/cValue alınamadı, maksimum deneme sayısı aşıldı")

def get_page(url, cookies=None):
    """Sayfa içeriğini alır (Cloudflare bypass ile)"""
    logger.info(f"Sayfa alınıyor: {url}")
    
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Connection': 'keep-alive',
        'Referer': 'https://dizipal935.com/',
        'Upgrade-Insecure-Requests': '1',
    }
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            scraper = create_scraper()
            response = scraper.get(
                url,
                headers=headers,
                cookies=cookies,
                timeout=15
            )
            response.raise_for_status()
            
            # Cloudflare engeli kontrolü
            if "Attention Required! | Cloudflare" in response.text:
                raise RuntimeError("Cloudflare engeli algılandı")
                
            return response.text
        
        except Exception as e:
            logger.error(f"Hata (Deneme {attempt+1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                sleep_time = (attempt + 1) * 2 + random.uniform(0.5, 2.5)
                logger.info(f"{sleep_time:.1f} saniye sonra yeniden denenecek...")
                time.sleep(sleep_time)
    
    raise RuntimeError(f"Sayfa alınamadı: {url}")

def decrypt_data(encrypted_data, cKey, cValue):
    """Şifreli veriyi çözer"""
    logger.info("Şifre çözme işlemi başlatılıyor")
    
    try:
        # Base64 decode
        data = base64.b64decode(encrypted_data)
        
        # Salt ve IV'yi ayır (ilk 16 byte salt, sonraki 16 byte IV)
        salt = data[:16]
        iv = data[16:32]
        ciphertext = data[32:]
        
        # Anahtar türetme
        password = f"{cKey}{cValue}".encode()
        key = PBKDF2(password, salt, dkLen=32, count=1000)
        
        # AES şifre çözme
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        
        result = decrypted.decode('utf-8')
        logger.info("Şifre çözme başarılı")
        logger.debug(f"Çözülen içerik: {result[:100]}...")
        return result
        
    except Exception as e:
        logger.error(f"Şifre çözme hatası: {str(e)}")
        raise

def get_iframe_content(url):
    """Iframe içeriğini alır"""
    logger.info(f"Iframe URL'sine erişiliyor: {url}")
    
    headers = {
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7',
        'Connection': 'keep-alive',
        'Host': url.split('/')[2],
        'Referer': 'https://dizipal935.com/',
        'Sec-Fetch-Dest': 'iframe',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'cross-site',
        'Upgrade-Insecure-Requests': '1',
        'User-Agent': random.choice(USER_AGENTS)  # Rastgele User-Agent
    }
    
    max_retries = 3
    for attempt in range(max_retries):
        try:
            # Cloudflare engeli için scraper kullan
            scraper = create_scraper()
            response = scraper.get(url, headers=headers, timeout=20)
            
            # Cloudflare engeli kontrolü
            if "Attention Required! | Cloudflare" in response.text:
                raise RuntimeError("Cloudflare engeli algılandı")
                
            response.raise_for_status()
            
            # Debug için kaydet
            with open('iframe_content.html', 'w', encoding='utf-8') as f:
                f.write(response.text)
                
            return response.text
        
        except Exception as e:
            logger.error(f"Iframe hatası (Deneme {attempt+1}/{max_retries}): {str(e)}")
            if attempt < max_retries - 1:
                sleep_time = (attempt + 1) * 3 + random.uniform(1, 5)
                logger.info(f"{sleep_time:.1f} saniye sonra yeniden denenecek...")
                time.sleep(sleep_time)
    
    raise RuntimeError(f"Iframe içeriği alınamadı: {url}")

def extract_video_url(iframe_content):
    """Iframe içeriğinden video URL'sini çıkarır"""
    logger.info("Video URL aranıyor...")
    
    # Direkt video etiketi arama
    soup = BeautifulSoup(iframe_content, 'html.parser')
    video_tag = soup.find('video')
    
    if video_tag:
        source = video_tag.find('source')
        if source and source.get('src'):
            video_url = source.get('src')
            logger.info(f"Video URL bulundu: {video_url}")
            return video_url
    
    # JavaScript içinde video URL arama
    pattern = r'(https?://[^\s"\'<>]+?\.(?:mp4|m3u8)[^\s"\']*)'
    match = re.search(pattern, iframe_content)
    
    if match:
        video_url = match.group(0)
        logger.info(f"Video URL bulundu: {video_url}")
        return video_url
    
    # DPlayer kontrolü
    dplayer_pattern = r'var\s+dp\s*=\s*new\s+DPlayer\({\s*.*?url\s*:\s*["\'](https?://[^\s"\'<>]+?)["\']'
    dplayer_match = re.search(dplayer_pattern, iframe_content, re.DOTALL)
    
    if dplayer_match:
        video_url = dplayer_match.group(1)
        logger.info(f"DPlayer URL bulundu: {video_url}")
        return video_url
    
    logger.warning("Video URL bulunamadı")
    return None

def process_episode_page(episode_url, cookies, cKey, cValue):
    """Bölüm sayfasını işler ve video URL'sini döndürür"""
    logger.info(f"Bölüm işleniyor: {episode_url}")
    
    try:
        # Sayfayı al
        content = get_page(episode_url, cookies)
        soup = BeautifulSoup(content, 'html.parser')
        
        # Şifreli JSON verisini bul
        script_tags = soup.find_all('script')
        encrypted_data = None
        
        for script in script_tags:
            if script.string and 'encryptedData' in script.string:
                match = re.search(r'encryptedData\s*=\s*"([^"]+)"', script.string)
                if match:
                    encrypted_data = match.group(1)
                    break
        
        if not encrypted_data:
            logger.warning("Şifreli JSON bulunamadı")
            return None
        
        logger.info("Şifreli JSON bulundu")
        
        # JSON verisini çöz
        decrypted_json = decrypt_data(encrypted_data, cKey, cValue)
        json_data = json.loads(decrypted_json)
        
        # Iframe URL'sini al
        iframe_src = json_data.get('src')
        if not iframe_src:
            logger.warning("Iframe URL bulunamadı")
            return None
        
        logger.info(f"Çözülen iframe URL: {iframe_src}")
        
        # Iframe içeriğini al
        iframe_content = get_iframe_content(iframe_src)
        
        # Video URL'sini çıkar
        video_url = extract_video_url(iframe_content)
        return video_url
        
    except Exception as e:
        logger.error(f"Bölüm işleme hatası: {str(e)}")
        return None

def main():
    """Ana işlem fonksiyonu"""
    try:
        # Oturum başlat
        cookies, cKey, cValue = get_cookies_and_cKey_cValue()
        
        # Ana sayfayı al
        home_url = "https://dizipal935.com/yabanci-dizi-izle"
        home_content = get_page(home_url, cookies)
        
        # Dizi listesini çıkar
        soup = BeautifulSoup(home_content, 'html.parser')
        series_items = soup.select('.serie-item')
        logger.info(f"Ana sayfada bulunan öğe sayısı: {len(series_items)}")
        
        results = []
        
        # Her dizi için işlem yap
        for item in series_items[:3]:  # Test için ilk 3 dizi
            try:
                title = item.select_one('.serie-title').text.strip()
                link = item.select_one('a')['href']
                
                if not link.startswith('http'):
                    link = f"https://dizipal935.com{link}"
                
                logger.info(f"İşleniyor: {title} ({link})")
                
                # Bölüm sayfası URL'sini oluştur (ilk bölüm)
                episode_url = link.replace('/series/', '/bolum/') + '-1x1'
                
                # Video URL'sini al
                video_url = process_episode_page(episode_url, cookies, cKey, cValue)
                
                if video_url:
                    results.append({
                        'dizi': title,
                        'bölüm': '1x1',
                        'video_url': video_url
                    })
            except Exception as e:
                logger.error(f"Dizi işleme hatası: {str(e)}")
        
        # Sonuçları kaydet
        with open('dizipal_sonuclar.json', 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
            
        logger.info(f"Toplam {len(results)} video bulundu ve kaydedildi")
        
    except Exception as e:
        logger.error(f"Ana işlem hatası: {str(e)}")

if __name__ == "__main__":
    main()
