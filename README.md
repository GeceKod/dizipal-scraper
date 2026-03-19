# Dizipal Scraper

Bu repo, `dizipal1542.com` yonlendirmesiyle acilan guncel Dizipal yapisi icin hazirlanmis scraper dosyalarini ve yarim saatte bir calisacak GitHub Actions workflow'unu icerir.

## Neden proxy gerekiyor?

`19 Mart 2026` itibariyle site, GitHub-hosted runner IP'lerine `403` + Cloudflare challenge donuyor. Bu nedenle workflow, GitHub-hosted runner uzerinde calisabilmek icin `SCRAPER_PROXY` adinda bir GitHub Secret bekler.

## Beklenen kurulum

1. Repo `Settings > Secrets and variables > Actions` altina `SCRAPER_PROXY` secret'ini ekleyin.
2. Format:
   - Auth yoksa: `host:port`
   - Auth varsa: `kullanici:sifre@host:port`
3. Proxy tarafinda residential veya Cloudflare'a takilmayan benzeri bir cikis kullanin.
4. Workflow calistiginda sira su sekilde ilerler:
   - `main_dizi.py`
   - `main_film.py`
   - `json_birlestir.py`
5. Degisen JSON ciktilari otomatik commit/push edilir.

## Not

Kod hem HTTP isteklerinde hem de SeleniumBase tarayicisinda ayni proxy'yi kullanacak sekilde hazirlanmistir.

## Manuel calistirma

GitHub Actions sekmesinden `Dizipal Scraper` workflow'unu `Run workflow` ile manuel de baslatabilirsiniz.
