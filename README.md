# Dizipal Scraper

Bu repo, `dizipal1542.com` yonlendirmesiyle acilan guncel Dizipal yapisi icin hazirlanmis scraper dosyalarini ve yarim saatte bir calisacak GitHub Actions workflow'unu icerir.

## Neden self-hosted runner?

`19 Mart 2026` itibariyle site, GitHub-hosted runner IP'lerine `403` + Cloudflare challenge donuyor. Bu yuzden workflow `self-hosted` Windows runner kullanacak sekilde ayarlanmistir.

## Beklenen kurulum

1. GitHub repo ayarlarindan bu repo icin bir Windows self-hosted runner ekleyin.
2. Runner'i servis olarak degil, masaustu oturumu acik bir kullanici altinda interaktif calistirin.
3. Chrome/Edge kurulu oldugundan emin olun.
4. Workflow calistiginda sira su sekilde ilerler:
   - `main_dizi.py`
   - `main_film.py`
   - `json_birlestir.py`
5. Degisen JSON ciktilari otomatik commit/push edilir.

## Manuel calistirma

GitHub Actions sekmesinden `Dizipal Scraper` workflow'unu `Run workflow` ile manuel de baslatabilirsiniz.
