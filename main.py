import asyncio
from dizipal_scraper import DizipalScraper
from extractor import ContentXExtractor
from bs4 import BeautifulSoup
import re # iFrame kayna\u011F\u0131 i\u00E7in
from requests_handler import request_handler # \u0130stek y\u00F6neticisi

async def main():
    dizipal_scraper = DizipalScraper()
    contentx_extractor = ContentXExtractor()

    # Dizipal oturumunu ba\u015Flat ve cKey, cValue al
    session_initialized = await dizipal_scraper.init_session()
    if not session_initialized:
        print("Dizipal oturumu ba\u015Flat\u0131lamad\u0131. \u00C7\u0131k\u0131l\u0131yor.")
        return

    # "Yeni Eklenen Bölümler"i \u00E7ek (Kotlin kodundaki varsay\u0131lan kategori)
    print("\n--- Yeni Eklenen B\u00F6l\u00FCmler ---")
    latest_episodes = await dizipal_scraper.get_main_page_content(request_name="Yeni Eklenen Bölümler")
    
    all_m3u8_links = []
    processed_urls = set() # Duplicate i\u00E7in
    
    for item in latest_episodes:
        if item['url'] in processed_urls:
            continue
        processed_urls.add(item['url'])

        print(f"İşleniyor: {item['title']} - {item['url']}")
        
        # Film/Dizi detay sayfas\u0131n\u0131 \u00E7ekerek oynat\u0131c\u0131 iframe'ini bul
        detail_page_resp = request_handler.get(item['url'], headers={"Referer": dizipal_scraper.main_url, "User-Agent": request_handler.user_agent})
        if detail_page_resp:
            detail_soup = BeautifulSoup(detail_page_resp.text, 'html.parser')
            # Kotlin kodunda 'loadExtractor(iframe, ...)' \u00E7a\u011Fr\u0131l\u0131yor.
            # Dolay\u0131s\u0131yla burada iframe'i bulmam\u0131z laz\u0131m.
            # Dizipal'in g\u00FCncel HTML yap\u0131s\u0131na g\u00F6re bu se\u00E7iciyi ayarlaman\u0131z gerekebilir.
            # Bilinen extractor domainlerini i\u00E7eren iframe'leri ara
            iframe_tag = detail_soup.find('iframe', {'src': re.compile(r'(contentx\.me|hotlinger\.com|playru\.net|dplayer82\.site)')})
            
            player_url = None
            if iframe_tag:
                player_url = iframe_tag.get('src')
            
            # E\u011Fer iframe bulunamad\u0131ysa, Kotlin'deki "loadExtractor" fonksiyonu
            # bazen direk player URL'ini de alabilir. Sayfa i\u00E7indeki script'lere bakmak gerekebilir.
            # Bu b\u00F6l\u00FCm, Dizipal'in video g\u00F6mme y\u00F6ntemine g\u00F6re de\u011Fi\u015Febilir.
            # \u0130lk deneme olarak iframe'i ar\u0131yoruz.

            if player_url:
                extractor_referer = item['url'] # Extractor'a g\u00F6nderilecek referer, detay sayfas\u0131 olmal\u0131
                m3u8_results = await contentx_extractor.get_m3u8_link(player_url, extractor_referer)
                for link_info in m3u8_results:
                    print(f"  -> {link_info['quality']} m3u8: {link_info['url']}")
                    all_m3u8_links.append(link_info['url'])
            else:
                print(f"  Oynat\u0131c\u0131 iframe'i veya do\u011Frudan oynat\u0131c\u0131 URL'i bulunamad\u0131 {item['url']}")
        else:
            print(f"  Detay sayfas\u0131 al\u0131namad\u0131 {item['url']}")

    print("\n--- T\u00FCm Toplanan m3u8 Linkleri ---")
    for link in all_m3u8_links:
        print(link)

if __name__ == "__main__":
    asyncio.run(main())
