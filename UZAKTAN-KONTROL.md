# Uzaktan Kontrol

Windows, macOS ve Linux bilgisayarları; masaüstünden, Android'den ve iOS'tan
kontrol etmek için kendi sunucunda çalışan bir uzak masaüstü sistemi.
Uygulamalar [RustDesk](https://github.com/rustdesk/rustdesk) (AGPL-3.0) üzerine kurulu.

```
 Bilgisayar / telefon  ──P2P veya aktarıcı, uçtan uca şifreli──  Bilgisayar
          │                                                          │
          └──────────────── senin VPS'in (server/) ──────────────────┘
               hbbs: ID sunucusu    hbbr: aktarıcı
               account: hesap + adres defteri + web paneli (HTTPS)
```

## Klasörler

| Klasör | İçerik |
|---|---|
| (kök) | Uygulamaların kaynağı (RustDesk fork'u). Değişiklikler aşağıda. |
| `server/account-server/` | Hesap sunucusu (Python/FastAPI, SQLite) ve web paneli |
| `server/deploy/` | VPS için `docker compose` kurulumu |

## Bağlantı kuralları

- **Hesabına eklenmiş bilgisayar:** Uygulamada hesabınla giriş yaptığın her
  bilgisayar otomatik olarak hesabına eklenir. Aynı hesapla giriş yapmış başka
  bir cihazdan bu bilgisayara **kod sorulmadan** bağlanırsın.
- **Hesabında olmayan bilgisayar:** Ekranda görünen tek kullanımlık kod
  istenir. Kod her başarılı bağlantıdan sonra kendiliğinden değişir, yani her
  seferinde yeni kod gerekir. 10 yanlış denemede de kod yenilenir.

### Nasıl çalışıyor

1. Bilgisayarda hesaba giriş yapınca sunucu o bilgisayarı (ID ve UUID ile) hesaba bağlar.
2. Bilgisayarın arka plan servisi her heartbeat'te kalıcı şifresinin tuzlu
   özetini (h1) **kendi cihaz anahtarıyla (ed25519) imzalayıp** gönderir.
   Kalıcı şifre yoksa 32 karakterlik rastgele bir şifre üretilir.
   Sunucu ilk anahtarı sabitler (pin), sonrasında farklı bir anahtarın gönderdiği özetleri reddeder.
3. Sunucu bu özeti yalnızca o hesabın adres defterine koyar. Uygulama,
   adres defterindeki özetle doğrudan giriş yapar. Gerçek şifre hiçbir zaman ağa çıkmaz.
4. Bilgisayarı web panelinden kaldırırsan cihaz bunu bir sonraki heartbeat'te
   öğrenir. Şifreyi kendisi üretmişse şifreyi değiştirir; böylece eski özet işe yaramaz hale gelir.

## Sürükle-bırak dosya aktarımı

- **Uzak masaüstü penceresine bırak:** Kendi bilgisayarından dosya veya klasörleri
  uzak ekranın üstüne sürükleyip bırakırsın. Mevcut oturumun yetkisiyle arka planda bir dosya
  aktarım oturumu açılır (kod tekrar sorulmaz) ve dosyalar uzak bilgisayardaki
  açık klasöre (ilk seferde ev klasörüne) gönderilir. İlerleme dosya aktarım penceresinde görünür.
- **Dosya aktarım penceresi:** Yerel ve uzak paneller arasında dosyaları
  sürükleyip her iki yöne gönderebilirsin (birden fazla seçim de sürüklenir).
  Masaüstünden uzak panele bırakma da çalışır.
- Kopyala-yapıştır ile dosya aktarımı RustDesk'te zaten var (Ayarlar → Güvenlik → "Dosya kopyala-yapıştır").

## 1. Sunucuyu kur (VPS)

Gereken: Docker kurulu bir VPS ve ona yönlenmiş bir alan adı (ör. `uzak.alanadin.com`).
Açılması gereken portlar: TCP 80, 443, 21115-21119 ve UDP 21116.

```bash
git clone https://github.com/<kullanıcı-adın>/uzaktan-kontrol.git && cd uzaktan-kontrol/server/deploy
cp .env.example .env    # DOMAIN, ADMIN_USERNAME, ADMIN_PASSWORD değerlerini doldur
docker compose up -d --build
cat data/relay/id_ed25519.pub   # uygulamalara girilecek anahtar
```

Ardından `https://DOMAIN` adresindeki web paneline gir. Buradan şunları yapabilirsin:
- **İki adımlı doğrulamayı aç** (önerilir: hesabın tüm bilgisayarlarının anahtarıdır).
- Bilgisayarlarını gör (çevrimiçi durumu, kodsuz erişimin hazır olup olmadığı) ve kaldır.
- Uygulamalara girilecek sunucu ayarlarını gör.

Kullanıcı yönetimi (sunucuda):

```bash
docker compose exec -u app account python -m app.cli adduser ayse
docker compose exec -u app account python -m app.cli passwd baris
docker compose exec -u app account python -m app.cli reset-2fa baris
```

### Ev sunucusuna (CasaOS) kurulum

CasaOS altta normal Docker kullandığı için yukarıdaki kurulum aynen çalışır.
Ev ağında ek olarak şunlar gerekir:

**a) Dışarıdan erişilebilir misin? (CGNAT kontrolü)**
Modem arayüzündeki WAN IP adresini https://ifconfig.me adresinin gösterdiği IP ile karşılaştır.
Farklıysa ya da WAN IP `100.64.x.x`–`100.127.x.x` aralığındaysa operatörün CGNAT kullanıyordur. Bu durumda port yönlendirme işe yaramaz.
Operatörden "statik/gerçek IP" iste ya da sunucuyu küçük bir VPS'e taşı.

**b) Alan adı (dinamik DNS)**
Ev IP'n değişebildiği için https://www.duckdns.org adresinden ücretsiz bir ad al
(ör. `benimevim.duckdns.org`). IP'yi güncel tutmak için modemindeki DDNS özelliğini ya da CasaOS App Store'daki DuckDNS uygulamasını kullan.

**c) Modemde port yönlendirme** (hepsi CasaOS makinesinin yerel IP'sine)

| Port | Protokol | Ne için |
|---|---|---|
| 21115–21119 | TCP | ID sunucusu ve aktarıcı |
| 21116 | UDP | ID sunucusu |
| 443 | TCP | Web paneli / API (HTTPS) |

**d) Kurulum: CasaOS arayüzünden (önerilen)**

1. [`server/casaos/docker-compose.yml`](server/casaos/docker-compose.yml) dosyasının içeriğini kopyala.
2. Bir metin düzenleyicide `uzak.alanadin.com` geçen her yeri kendi alan adınla değiştir (4 yer). `ADMIN_PASSWORD` satırına güçlü bir şifre yaz.
3. CasaOS → **Uygulama Mağazası** → sağ üstteki **+** → **Özel Uygulama Kur** → **İçe Aktar** → metni yapıştır → **Gönder** → **Kur**.
4. Anahtar dosyası: CasaOS **Dosyalar** → `/DATA/AppData/uzaktan-kontrol/relay/id_ed25519.pub`.

Hesap sunucusunun imajı (`ghcr.io/bariscagriyuce/uzaktan-kontrol-account`) GitHub Actions ile otomatik derlenir.

**d2) Kurulum: terminalden** (CasaOS'a SSH ile bağlan ya da CasaOS'un terminalini kullan)

```bash
cd /DATA
git clone https://github.com/<kullanıcı-adın>/uzaktan-kontrol.git
cd uzaktan-kontrol/server/deploy
cp .env.example .env
nano .env        # DOMAIN, ADMIN_USERNAME, ADMIN_PASSWORD
docker compose up -d --build
cat /DATA/AppData/uzaktan-kontrol/relay/id_ed25519.pub   # anahtar
```

Konteynerler CasaOS panelinde görünür; oradan başlatıp durdurabilir ve kayıtlarını izleyebilirsin.
Veriler `/DATA/AppData/uzaktan-kontrol` klasöründe durur, yedeklemen gereken yer burası.

- **80. port doluysa** (CasaOS paneli genelde 80'dedir) `.env` içinde `HTTP_PORT=8088` yap.
  HTTPS sertifikası 443 üzerinden alınır, 80'e gerek yoktur.
- **443 başka bir uygulamada** (ör. Nginx Proxy Manager) kullanılıyorsa `caddy` servisini sil.
  Proxy'de alan adını `http://<sunucu-ip>:8000` adresine yönlendir ve `account` servisine `ports: ["8000:8000"]` ekle.
- **Evdeyken alan adı açılmıyorsa** modemin NAT loopback (hairpin) desteklemiyor demektir.
  Ev içi bağlantılar yine çalışır, çünkü uygulama aynı ağdaki cihazları kendisi bulur. Ancak hesap girişi için dışarıdan bir ağ (ör. mobil veri) gerekebilir.

## 2. Uygulamaları derle

### Önerilen: GitHub Actions (tüm platformlar)

Depo ayarlarında
**Settings → Secrets and variables → Actions → Variables** bölümüne şunları ekle:

| Değişken | Değer |
|---|---|
| `UK_SERVER` | `uzak.alanadin.com` |
| `UK_KEY` | `id_ed25519.pub` içeriği |
| `UK_API_SERVER` | `https://uzak.alanadin.com` |

Sonra **Actions → Flutter Nightly Build → Run workflow** ile derlemeyi başlat. Windows
(.exe/.msi), macOS (.dmg), Linux (.deb/.rpm/AppImage/Flatpak), Android (.apk)
paketleri çıkar. Sunucu bilgileri uygulamaya gömülü gelir, cihazlarda ayar yapman gerekmez.
iOS için Apple geliştirici hesabı ve imzalama gerekir.

### Değişkenleri gömmeden kullanmak

Resmi yapıyı da kullanabilirsin: her cihazda **Ayarlar → Ağ → ID/Aktarıcı
sunucusu** bölümüne ID sunucusu, aktarıcı, API (`https://DOMAIN`) ve anahtarı gir.
Kodsuz bağlantı ve sürükle-bırak için ise bu depodaki değişikliklerle derlenmiş sürüm gerekir.

## İstemcide yapılan değişiklikler

| Dosya | Değişiklik |
|---|---|
| `src/hbbs_http/sync.rs` | Hesaba katılma, imzalı şifre özeti gönderme, gerekirse kalıcı şifre üretme, hesaptan çıkınca şifreyi değiştirme |
| `libs/base/src/config/keys.rs` | `account-enrolled` ve `account-managed-password` seçenekleri |
| `libs/hbb_common/src/config.rs`, `src/common.rs` | `UK_SERVER` / `UK_KEY` / `UK_API_SERVER` ile sunucuyu derlemeye gömme |
| `flutter/lib/desktop/pages/remote_page.dart` | Uzak ekrana dosya bırakma ve "Dosyaları bırakın" katmanı |
| `flutter/lib/desktop/pages/file_manager_page.dart` | Bekleyen yüklemeler, paneller arası sürükle-bırak, masaüstünden bırakmadaki yön hatasının düzeltilmesi |
| `flutter/lib/common.dart`, `utils/multi_window_manager.dart`, `desktop_home_page.dart`, `file_manager_tab_page.dart` | Bırakılan dosyaların pencereler arasında aktarılması; bağlanmadan önce adres defterinin tazelenmesi |

## Güvenlik notları

- Hesap şifresi, hesaptaki bütün bilgisayarların anahtarı demek. Güçlü bir şifre kullan ve 2FA'yı aç.
- Hesap sunucusu şifreleri scrypt ile saklar. Oturum belirteçlerinin yalnızca SHA-256 özeti tutulur. Girişlerde deneme sınırı vardır (IP başına 15 dakikada 10 deneme).
- Adres defterindeki özetler şifrenin kendisi değildir ama o cihaza giriş için yeterlidir. Bu yüzden sunucu verisini (`server/deploy/data/`) gizli tut ve yedekle.
- ID ve aktarıcı sunucusu anahtarı olmayan istemcileri reddeder. Bağlantılar uçtan uca şifrelidir.
- Uzak bilgisayarda "Bağlantıyı yalnızca onay ile kabul et" seçiliyse kodsuz giriş de onay bekler.

## Testler

```bash
cd server/account-server
python -m venv .venv && .venv/bin/pip install -r requirements.txt pytest httpx
.venv/bin/python -m pytest tests
```

## Lisans

İstemci RustDesk'ten türetildiği için AGPL-3.0 lisanslıdır. Uygulamayı başkalarına
dağıtırsan kaynak kodunu da paylaşman gerekir.
