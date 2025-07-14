import asyncio
from dizipal_scraper import DizipalScraper
from extractor import ContentXExtractor
import re

async def main():
    dizipal_scraper = DizipalScraper()
    contentx_extractor = ContentXExtractor()

    if not await dizipal_scraper.init_session():
        print("Dizipal oturumu başlatılamadı. Çıkılıyor.", flush=True)
        return

    print("\n--- Yeni Eklenen Bölümler Taranıyor ---", flush=True)
    latest_episodes = await dizipal_scraper.get_main_page_content(request_name="Yeni Eklenen Bölümler")
    
    if not latest_episodes:
        print("Yeni eklenen bölüm bulunamadı veya alınamadı.", flush=True)
        return

    all_m3u8_links = []
    processed_urls = set()

    # Kotlin kodlarından anlaşıldığı üzere bu alan adları ContentX ile aynı mantığı kullanıyor.
    contentx_variants = ["contentx", "dplayer82", "playru", "pichive", "hotlinger"]

    for item in latest_episodes:
        if item['url'] in processed_urls:
            continue
        processed_urls.add(item['url'])

        print(f"\nİşleniyor: {item['title']} ({item['url']})", flush=True)
        
        player_url = await dizipal_scraper.get_player_url(item['url'])
        
        if player_url:
            # Eğer URL "//" ile başlıyorsa başına "https:" ekle
            if player_url.startswith("//"):
                player_url = "https:" + player_url

            print(f"  -> Oynatıcı URL'i çözüldü: {player_url}", flush=True)
            
            # player_url'in bilinen ContentX varyantlarından birini içerip içermediğini kontrol et
            if any(variant in player_url for variant in contentx_variants):
                m3u8_results = await contentx_extractor.get_m3u8_link(player_url, referer=item['url'])
                for link_info in m3u8_results:
                    print(f"  --> Bulunan {link_info['quality']} m3u8: {link_info['url']}", flush=True)
                    all_m3u8_links.append(link_info['url'])
            else:
                print(f"  -> Desteklenmeyen extractor: {player_url}", flush=True)
        else:
            print(f"  -> Bu bölüm için oynatıcı URL'i alınamadı.", flush=True)

    print("\n--- Tarama Tamamlandı ---", flush=True)
    if all_m3u8_links:
        print(f"Toplam {len(all_m3u8_links)} adet M3U8 linki bulundu.", flush=True)
        try:
            with open("m3u8_links.txt", "w", encoding="utf-8") as f:
                for link in all_m3u8_links:
                    f.write(link + "\n")
            print("Tüm linkler 'm3u8_links.txt' dosyasına başarıyla yazıldı.", flush=True)
        except Exception as e:
            print(f"Dosyaya yazma sırasında bir hata oluştu: {e}", flush=True)
    else:
        print("Hiç M3U8 linki bulunamadı.", flush=True)

if __name__ == "__main__":
    asyncio.run(main())
