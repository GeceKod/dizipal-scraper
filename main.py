import asyncio
from dizipal_scraper import DizipalScraper
from extractor import ContentXExtractor
import re

async def main():
    dizipal_scraper = DizipalScraper()
    contentx_extractor = ContentXExtractor()

    # Dizipal oturumunu başlat
    if not await dizipal_scraper.init_session():
        print("Dizipal oturumu başlatılamadı. Çıkılıyor.")
        return

    # Sadece "Yeni Eklenen Bölümler" listesini çekiyoruz
    print("\n--- Yeni Eklenen Bölümler Taranıyor ---")
    latest_episodes = await dizipal_scraper.get_main_page_content(request_name="Yeni Eklenen Bölümler")
    
    if not latest_episodes:
        print("Yeni eklenen bölüm bulunamadı veya alınamadı.")
        return

    all_m3u8_links = []
    processed_urls = set()  # Tekrarlanan URL'leri işlememek için

    for item in latest_episodes:
        if item['url'] in processed_urls:
            continue
        processed_urls.add(item['url'])

        print(f"\nİşleniyor: {item['title']} ({item['url']})")
        
        # Bölüm sayfasından şifreli oynatıcı URL'ini çöz
        # Bu URL, contentx.me, rapidvid.net gibi bir extractor URL'i olacak
        player_url = await dizipal_scraper.get_player_url(item['url'])
        
        if player_url:
            print(f"  -> Oynatıcı URL'i çözüldü: {player_url}")
            
            # Hangi extractor'ı kullanacağımızı URL'den anlıyoruz (şimdilik sadece ContentX)
            if "contentx" in player_url:
                m3u8_results = await contentx_extractor.get_m3u8_link(player_url, referer=item['url'])
                for link_info in m3u8_results:
                    print(f"  --> Bulunan {link_info['quality']} m3u8: {link_info['url']}")
                    all_m3u8_links.append(link_info['url'])
            else:
                # Diğer extractor'lar için buraya 'elif' blokları eklenebilir
                print(f"  -> Desteklenmeyen extractor: {player_url}")
        else:
            print(f"  -> Bu bölüm için oynatıcı URL'i alınamadı.")

    print("\n--- Tarama Tamamlandı ---")
    if all_m3u8_links:
        print(f"Toplam {len(all_m3u8_links)} adet M3U8 linki bulundu.")
        try:
            with open("m3u8_links.txt", "w", encoding="utf-8") as f:
                for link in all_m3u8_links:
                    f.write(link + "\n")
            print("Tüm linkler 'm3u8_links.txt' dosyasına başarıyla yazıldı.")
        except Exception as e:
            print(f"Dosyaya yazma sırasında bir hata oluştu: {e}")
    else:
        print("Hiç M3U8 linki bulunamadı.")

if __name__ == "__main__":
    asyncio.run(main())
