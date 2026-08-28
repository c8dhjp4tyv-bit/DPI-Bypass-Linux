<div align="center">

<img src="data/icons/hicolor/256x256/apps/xyz.atomland.DpiBypass.png" width="128" alt="DPI Bypass">

# DPI Bypass

**Türkiye'deki DPI tabanlı engelleri aşan, ağ değiştiğinde yöntemi kendiliğinden
yeniden bulan GNOME uygulaması.**

Discord başta olmak üzere derin paket incelemesi (DPI) ile engellenen sitelere
erişimi açar. VPN değildir: trafik başka bir ülkeye çıkmaz, ping ve gecikme
atlatma için başka bir sunucuya taşınmaz. İsteğe bağlı **Ping düşürme (Beta)**
kipi ise yalnız bilgisayardaki doğrulanabilir yerel gecikme nedenlerini ölçer.

*Yazan: Atom Gamer Arda A.G.A*

</div>

---

## Tek satırlık kurulum

```bash
curl -fsSL https://raw.githubusercontent.com/atomgameraga/DPI-Bypass-Linux/main/install.sh | sudo bash
```

Betik işletim sistemini kendi saptar, gereken paketleri kurar, servisi
etkinleştirir ve bitince **"Buradan sonrasına GUI uygulamasından devam edin"**
der. Uygulamayı Etkinlikler menüsünde **DPI Bypass** adıyla bulursunuz.

Desteklenen dağıtımlar: **Fedora / RHEL / Rocky / Alma, Ubuntu / Debian / Mint /
Pop!\_OS / Kali, Arch / Manjaro / EndeavourOS, openSUSE, Alpine, Void, Solus**
ve `dnf / apt / pacman / zypper / apk / xbps / eopkg` kullanan diğerleri.

Kaldırmak için:

```bash
sudo bash install.sh --uninstall
```

---

## Ne yapıyor?

| Katman | Yapılan iş |
|---|---|
| **DNS** | Sistemin tüm DNS trafiği (53/udp, 53/tcp) yerel köprüye yönlendirilir ve **DNS-over-HTTPS** ile taşınır. Birincil **Cloudflare**, yedekler **Google** ve **Quad9**. DNS zehirlenmesi ve DNS düzeyindeki engel böylece tamamen aşılır. |
| **DPI** | Engelli hedeflere giden TCP 80/443 bağlantıları yerel şeffaf vekile düşer. İlk istemci verisi (TLS ClientHello / HTTP isteği) seçilen stratejiye göre yeniden şekillendirilerek gönderilir; sunucu veriyi eksiksiz alır, yol üstündeki DPI ise SNI'yi göremez. |
| **QUIC** | İsteğe bağlı olarak engelli hedeflere UDP/443 reddedilir; tarayıcılar atlatma uygulanabilen TCP'ye döner. |
| **Ping düşürme (Beta)** | Aktif fiziksel arayüzde donanıma uyarlanmış adayları (Wi-Fi güç tasarrufu, `fq_codel`/`fq`/`cake`, Ethernet EEE ve RX coalescing) tek tek uygulayıp ölçer, her denemeden sonra geri alır ve yalnız doğrulanmış kazancı olan adayı bırakır. Kazanç yoksa hiçbir ayar değişmez. |
| **Diğer trafik** | Yönlendirilmez. ICMP (ping), oyun/VoIP UDP trafiği, torrent, VPN — hiçbiri vekilden geçmez, ölçülebilir bir etki oluşmaz. |

### Atlatma yöntemleri

Hepsi kullanıcı alanında çalışır; çekirdek modülü ya da NFQUEUE gerekmez.

| Yöntem | Nasıl çalışır |
|---|---|
| `tlsrec` | ClientHello birden çok **TLS kaydına** bölünür. TLS açısından tamamen geçerlidir; kayıt katmanını birleştirmeyen DPI SNI'yi bulamaz. Ek gecikme yoktur. |
| `split` | İlk veri, SNI'nin ortasından ayrı TCP segmentlerine bölünür. |
| `disorder` | Baştaki parça **düşük TTL** ile gönderilir: DPI görür, sunucuya ulaşmaz. İkinci parça normal gider; çekirdek kayıp parçayı normal TTL ile yeniden iletir. DPI akışı eksik görür, sunucu eksiksiz alır. |
| `oob` | Parçaların arasına `MSG_OOB` ile "acil" bayt konur. Akışı satır içi birleştiren DPI bu baytı veriye katıp SNI'yi bozar; sunucunun TCP yığını acil baytı akıştan düşürür. |
| `disoob` | `disorder` + `oob`. |
| `fake` | Gerçek veriden önce, zararsız bir SNI taşıyan sahte bir ClientHello **ham soketle ve gerçek verinin sıra numarasıyla** düşük TTL kullanılarak gönderilir. Çekirdeğin gönderim kuyruğuna hiç girmediği için gerçek veri bozulmaz. |

Toplam 16 hazır varyant vardır (`dpi-bypass strategies`).

### Yöntem nasıl seçiliyor?

1. **Operatör saptanır.** Genel IP adresinden Team Cymru'nun DNS tabanlı IP→ASN
   servisiyle (DoH üzerinden) ASN ve AS adı okunur; buna bağlantı türü
   (wifi / ethernet / mobil) ve SSID eklenir. Ekrandaki listenin tamamı desteklenir:

   > Türk Telekom (Mobil) · Türk Telekom Evde İnternet · Türk Telekom Hotspot ·
   > Redbox (Türk Telekom) · Turkcell (Mobil) · Turkcell Superonline ·
   > Superbox (Turkcell FWA) · Turkcell Hotspot · Vodafone (Mobil) ·
   > Vodafone Evde İnternet · Vodafone Hotspot · TurkNet · Diğer / Bilinmiyor

2. **O operatörün sırası denenir.** Her yöntem `discord.com` üzerinde *gerçek*
   bir TLS el sıkışması + HTTP isteğiyle sınanır. "Bağlantı kuruldu" demek
   yetmez: DPI çoğu zaman TCP el sıkışmasına izin verip ClientHello'dan sonra
   RST gönderir; bu yüzden sunucudan gerçek yanıt beklenir.

3. **Çalışan yöntem ikinci bir uç noktayla doğrulanır** (`gateway.discord.gg`)
   ve o ağın parmak izine kaydedilir.

### Ağ değişince ne oluyor?

Çekirdekten gelen **netlink** olayları anında yakalanır. Ağ parmak izi
(arayüz + ağ geçidi + ağ geçidi MAC + SSID + bağlantı türü) değiştiğinde —
örneğin `atom` ağından `atoms hotspot` ağına geçtiğinizde — arama arka planda
yeniden başlar. O ağ daha önce görüldüyse kayıtlı yöntem **ilk sırada** denenir,
böylece geçiş çoğunlukla tek denemede ve saniyeler içinde tamamlanır.

Seçili yöntem sonradan çalışmayı bırakırsa (operatör kural değiştirirse)
başarısız bağlantılar sayılır ve arama kendiliğinden tekrarlanır.

### Her sitede çalışması

- Yerleşik listede Discord'un tüm alan adları ve Türkiye'de DPI ile engellendiği
  bilinen diğer adresler vardır.
- **Otomatik keşif:** açtığınız yeni bir alan adı, atlatmasız açılmayıp
  atlatmayla açılıyorsa sessizce sınanıp kalıcı olarak listeye eklenir.
- Dilediğiniz alan adını arayüzden elle de ekleyebilirsiniz (alt alan adları
  kapsanır).
- "Tüm siteler" kipinde 80/443'ün tamamı vekilden geçer.

---

## Ping düşürme (Beta)

Bu özellik bir VPN değildir; ISP rotasını, fiziksel mesafeyi veya uzak
sunucunun yükünü değiştiremez ve her ağda daha düşük ping garanti etmez. Esas
amacı bilgisayar kaynaklı yerel kuyruklanma ve jitter nedenlerini azaltmaktır.

### Nasıl çalışır: aday tabanlı ölçüm

Tek bir ayarı uygulayıp "oldu" demek yerine motor her adayı ayrı ayrı ölçer:

```
taban ölçüm
  → aday A uygula → ölç → geri al
  → aday B uygula → ölç → geri al
  → aday C uygula → ölç → geri al
  → istatistiksel olarak anlamlı kazancı olan en iyi adayı seç
  → uygula → bağımsız son doğrulama → kazanç tekrarlamazsa geri al
```

Her ölçüm noktası ısınma turu + birden çok ölçüm turu içerir. Varsayılan ağ
geçidi ile IP tabanlı kararlı uzak hedeflerden örnek alınır; median, minimum,
p95 RTT, jitter, yayılım (p95 − min) ve paket kaybı ayrı hesaplanır. ICMP
kullanılamazsa DNS çözümleme süresini karıştırmayan doğrudan TCP-connect
ölçümüne geçilir.

### Adaylar

Aday kümesi donanıma ve bağlantı türüne göre üretilir:

| Aday | Ne zaman | Ne yapar |
|---|---|---|
| Wi-Fi güç tasarrufu | kablosuz arayüzde `iw` varsa ve güç tasarrufu açıksa | `iw dev … set power_save off` — uyku/uyanma gecikmesini kaldırır |
| `fq_codel` / `fq` / `cake` | kök qdisc **yalnız** eksiksiz geri yüklenebilir basit bir FIFO ise (`pfifo`, `bfifo`, `pfifo_fast`); `cake` ayrıca `sch_cake` modülü varsa | kök qdisc'i değiştirir |
| EEE kapalı | Ethernet'te `ethtool --show-eee` "enabled" diyorsa | `ethtool --set-eee … eee off` — LPI uyanma gecikmesini kaldırır |
| Düşük gecikmeli RX coalescing | Ethernet'te `ethtool -c` okunabiliyor ve adaptive-rx açık / rx-usecs > 0 ise | `ethtool -C … adaptive-rx off rx-usecs 0` |

Tekil adaylardan birden fazlası kazanç sağlarsa birleşimi de ölçülür ve en
iyisi seçilir. Sürücü ya da araç desteklemiyorsa aday sessizce atlanır — hata
üretilmez. `cake`, `fq_codel`, `fq`, `mq`, `noqueue` ve tüm bilinmeyen/custom
qdisc yapıları korunur; kullanıcının kurduğu bir qdisc asla ezilmez.

### Kabul ve geri alma eşikleri

Gürültü kazanç sayılmaz: 20.1 ms → 19.8 ms reddedilir, 25 → 20 ms /
p95 55 → 31 ms / jitter 8 → 3 ms kabul edilir. Aşağıdakilerden biri olursa
değişiklik geri alınır:

- bağlantı kesilirse ya da ölçüm yöntemi değişirse,
- paket kaybı artarsa,
- median, p95 ya da jitter kötüleşirse,
- son doğrulamada kazanç tekrarlanmazsa,
- aday yarım uygulanırsa (uygulanan adımların hepsi geri alınır),
- ağ/arayüz değişirse,
- tarama sırasında ayar dışarıdan değiştirilirse (o zaman tarama durur ve
  araya giren ayar korunur).

### Ağ başına öğrenme

Doğrulanan en iyi aday ağ parmak izi ile `/var/lib/dpi-bypass/latency-profiles.json`
içinde saklanır. Aynı ağa dönüldüğünde önce o aday uygulanıp kısa bir
doğrulama yapılır; artık kazanç sağlamıyorsa geri alınır, kayıt silinir ve tam
tarama yeniden çalışır.

### Kapsam dışı

DNS, MTU, rota, DHCP, IPv6, firewall, TCP buffer/kalıcı sysctl, BBR, ECN ve
CPU governor ayarları bu kipin kapsamı dışındadır — hiçbiri bir oyunun UDP
RTT'sini düşürmez, bir kısmı bağlantıyı bozar. Gerçek bufferbloat ölçümü hattı
doyurmayı gerektirdiği için yapılmaz; ölçülmeyen bir değer ölçülmüş gibi de
gösterilmez. Doğrulanmış kazanç yoksa arayüz bunu açıkça söyler ve tahmini
milisaniye veya yüzde üretmez.

Servis kapanırken, ağ değişirken ve `dpi-bypassd --cleanup` çalışırken aynı
idempotent geri alma tarifi (`/run/dpi-bypass/latency.json`) kullanılır; servis
çökerse yeniden başladığında bu tarif önce uygulanır.

```bash
dpi-bypass latency status   # aday sonuçları, önce/sonra ölçüm ve kazanç
dpi-bypass latency on       # aday taramasını başlat (birkaç dakika sürebilir)
dpi-bypass latency off      # kipi kapat, tüm değişiklikleri geri al
dpi-bypass latency test     # yalnız ölç, hiçbir şeyi değiştirme
```

---

## Vodafone sınırsız modu

Vodafone'un "Red Sınırsız" tarifelerinde mobil veri sınırsızdır, ancak
**hotspot/tethering 15 GB ile sınırlıdır**. Operatör paylaşımı paketin **TTL**
(IPv6'da hop limit) değerinden anlar: telefonun kendi trafiği operatöre `64`
ile ulaşır, laptoptan gelen paket ise telefonda bir kez yönlendirildiği için
`63` olarak varır ve kotadan düşer.

Bu mod, bu bilgisayardan çıkan paketleri **TTL 65** ile yollar. Telefon bir
düşürünce operatöre tam `64` gider.

**Nasıl açılır:** Ayarlar → Gelişmiş → *Vodafone sınırsız modu*. Açarken
polkit üzerinden **yönetici parolası** sorulur. Komut satırından:

```bash
dpi-bypass vodafone status     # durum + paket sayacı
dpi-bypass vodafone on
dpi-bypass vodafone off
```

**Yalnızca kaydedildiği ağda çalışır.** Modu açtığınız andaki ağın parmak izi
kaydedilir; ev Wi-Fi'ına ya da Ethernet'e geçtiğinizde kural kendiliğinden
kalkar, telefona döndüğünüzde geri gelir. Kurallar `inet dpibypass_ttl`
tablosunda, `oifname` ile yalnızca ilgili arayüze bağlı olarak tutulur.

**Atlatma bozulmaz.** `disorder` ve `fake` stratejileri kasıtlı olarak düşük
TTL'li (2-8) paketler gönderir; bu paketlerin DPI'ı geçip sunucuya
*ulaşmaması* atlatmanın çalışma ilkesidir. Bu yüzden TTL yeniden yazımı
yalnızca TTL'i **32'nin üstünde** olan paketlere uygulanır. Eşik, bir test
(`test_ttl_guard_desync_stratejilerinin_uzerinde`) ile korunur: ileride daha
yüksek TTL'li bir strateji eklenirse test kırmızıya döner.

**IPv6.** Telefon tethering yaparken laptopa kendi global IPv6 adresini verir;
o zaman operatör aynı aboneden iki farklı IPv6 kaynağı görür ve hop limit ne
olursa olsun paylaşım anlaşılır. Bu yüzden mod, varsayılan olarak yalnızca
tethering arayüzünde IPv6'yı kapatır (`vodafone_disable_ipv6`) ve kapanırken
eski değeri geri yazar.

> **Polkit kapısı hakkında dürüst not:** `dpi-bypass` grubundaki bir kullanıcı
> zaten denetim soketine doğrudan `vodafone.enable` komutu yollayabilir. Yani
> parola sorma adımı **teknik bir güvenlik sınırı değildir**; sistem genelinde
> paket başlığı değiştiren bir ayarın yanlışlıkla ya da fark edilmeden
> açılmasını engelleyen bilinçli bir onay adımıdır.

> **Kullanım koşulları uyarısı:** Bu mod, operatör sözleşmenizin kullanım
> koşullarına aykırıdır. Otomatik sayacı atlatır, ancak çok yüksek kullanım
> (ayda yüzlerce GB üzeri) adil kullanım incelemesine takılabilir — orada
> TTL'in bir etkisi olmaz. Sorumluluk kullanıcıya aittir.

Kuralın gerçekten çalıştığını görmek için:

```bash
sudo nft list table inet dpibypass_ttl
sudo tcpdump -ni <arayüz> -v -c 5 'tcp port 443' | grep -o 'ttl [0-9]*'
```

---

## Arayüz

GTK4 + libadwaita ile yazılmıştır; GNOME'un kendi bileşenlerini kullanır
(`Adw.ViewStack`, `Adw.PreferencesPage`, `Adw.SwitchRow`, `Adw.ComboRow`,
`Adw.ToastOverlay`, `Adw.AboutDialog`…). Koyu/açık tema, dar ekran uyumu ve
libadwaita 1.2+ sürümleriyle geriye dönük uyumluluk vardır.

Sayfalar: **Durum** (tek dokunuşla aç/kapat, canlı bilgi, "yeniden ara" ve
"discord.com'u test et"), **Ayarlar**, **Siteler**, **Günlük**.

---

## Komut satırı

```bash
dpi-bypass status          # genel durum
dpi-bypass search --wait   # yöntemi yeniden ara
dpi-bypass test            # discord.com erişimini sına
dpi-bypass test oob-snimid # belirli bir yöntemi sına
dpi-bypass detect          # operatörü yeniden sapta
dpi-bypass strategies      # yöntem listesi
dpi-bypass logs -f         # canlı günlük
dpi-bypass set mode=all dns_provider=quad9
dpi-bypass disable / enable
dpi-bypass vodafone status  # hotspot TTL düzeltmesi (on / off)
dpi-bypass latency status   # Ping düşürme (on / off / test)
dpi-bypass doctor           # soket erişimi tanısı (grup / oturum / soket)
```

---

## Servis

Kurulum `dpi-bypass.service` birimini kaydeder ve etkinleştirir; **sistem
açılışında kendiliğinden başlar**.

```bash
systemctl status dpi-bypass
journalctl -u dpi-bypass -f
```

Servis durduğunda tüm çekirdek kuralları geri alınır (`ExecStopPost`), sistem
hiçbir zaman yarım kurulmuş kurallarla kalmaz.

`dpi-bypass` grubundaki kullanıcılar arayüzden servisi parola sormadan
yönetebilir (polkit kuralı kurulur). Kurulum betiği sizi bu gruba ekler.

### Denetim soketi ve grup erişimi

Servis `/run/dpi-bypass/daemon.sock` üzerinden yönetilir. Soket **root:dpi-bypass
/ 0660** olarak kurulur ve bu gerçekten uygulanıp uygulanmadığı `stat` ile
yeniden okunarak doğrulanır. Grup çözülemez ya da izinler uygulanamazsa soket
herkese açılmaz; yalnız root'a bırakılır (`0600`) ve servis günlüğüne hata
yazılır.

"Erişim reddedildi" hatasının tek bir sebebi yoktur; `dpi-bypass doctor` hangisi
olduğunu söyler:

| Durum | Anlamı | Çözüm |
|---|---|---|
| `group-missing` | `dpi-bypass` grubu sistemde yok | `sudo groupadd --system dpi-bypass` |
| `not-a-member` | Kullanıcı grup veritabanında üye değil | `sudo usermod -aG dpi-bypass $USER` ya da arayüzdeki **Erişimi onar** |
| `stale-session` | Kullanıcı üye ama **açık oturum** eski grup listesinde | Uygulama kendini `sg dpi-bypass -c …` ile yeniden başlatır |
| `no-socket` | Servis çalışmıyor | `sudo systemctl start dpi-bypass` |
| `socket-permissions` | Soketin grubu/kipi beklenenden farklı | `sudo systemctl restart dpi-bypass` |

`usermod -aG` **çalışan süreçlerin** ek gruplarını değiştirmez; bu yüzden
kurulumdan sonra grup eklense bile açık masaüstü oturumu eski listeyi taşır.
GUI ve komut satırı bu durumu ayırt eder ve `sg` ile bir kez (döngü koruması
ile) kendini yeniden başlatır — oturum kapatmak ya da yeniden başlatmak
gerekmez. `sg` yoksa bu açıkça söylenir.

---

## Ayarlar

`/etc/dpi-bypass/config.json`

| Anahtar | Varsayılan | Açıklama |
|---|---|---|
| `enabled` | `true` | Koruma açık mı |
| `mode` | `smart` | `smart` = yalnız engelli liste, `all` = tüm 80/443 |
| `isp` | `auto` | Operatör profili (`auto` ya da profil kimliği) |
| `strategy` | `auto` | Atlatma yöntemi (`auto` ya da yöntem adı) |
| `dns_provider` | `cloudflare` | `cloudflare` / `google` / `quad9` |
| `dns_intercept` | `true` | 53 numaralı portu yakala |
| `block_quic` | `true` | Engelli hedeflere UDP/443'ü reddet |
| `auto_switch` | `true` | Ağ değişince yeniden ara |
| `auto_discover` | `true` | Yeni engelli siteleri kendiliğinden bul |
| `recheck_interval` | `1800` | Düzenli denetim aralığı (saniye, 0 = kapalı) |
| `extra_domains` | `[]` | Elle eklenen alan adları |
| `gui_autostart` | `true` | Oturum açılışında arayüzü başlat |
| `latency_mode` | `false` | Ölçümlü düşük gecikme optimizasyonu |
| `vodafone_mode` | `false` | Vodafone sınırsız modu (hotspot TTL düzeltmesi) |
| `vodafone_networks` | `[]` | Modun etkin olacağı ağlar (en fazla 10) |
| `vodafone_ttl` | `65` | Giden paketlere yazılacak TTL (ileri düzey) |
| `vodafone_disable_ipv6` | `true` | Tethering arayüzünde IPv6'yı kapat |

Öğrenilen ağlar ve alan adları: `/var/lib/dpi-bypass/state.json`

---

## Gereksinimler

- Linux, systemd
- Python 3.8+
- nftables (yoksa iptables)
- iproute2/`tc`, `iw` ve `ethtool` (Ping düşürme adayları; yoksa güvenle atlanır)
- `sg` (shadow-utils) — grup üyeliği yeni eklendiğinde oturum kapatmadan uygulanır
- GTK 4 + libadwaita 1.2+ ve PyGObject (yalnızca arayüz için)
- Servis root olarak çalışır (`CAP_NET_ADMIN`, `CAP_NET_RAW`)

---

## Geliştirme

```bash
git clone https://github.com/atomgameraga/DPI-Bypass-Linux
cd DPI-Bypass-Linux
python3 -m unittest discover -s tests -v     # testler
sudo python3 bin/dpi-bypassd -v              # servisi kaynaktan çalıştır
python3 bin/dpi-bypass-gui                   # arayüzü kaynaktan çalıştır
sudo bash install.sh                         # yerel ağaçtan kur
```

Proje düzeni:

```
src/dpibypass/
  daemon.py      düzenleyici: saptama, arama, olay akışı
  desync.py      stratejilerin sokete uygulanması
  strategies.py  yöntem kataloğu
  rawfake.py     ham soketle sahte paket enjeksiyonu
  tlsutil.py     ClientHello ayrıştırma ve kayıt parçalama
  tlsclient.py   bellek BIO tabanlı TLS istemcisi (DoH ve testler için)
  resolver.py    DNS-over-HTTPS çözümleyici
  dnsserver.py   yerel DNS köprüsü
  proxy.py       şeffaf TCP vekil
  firewall.py    nftables / iptables kuralları
  latency.py     aday tabanlı ölçüm, güvenli runtime optimizasyonu, geri alma
  session_access.py  grup / oturum / soket erişim tanısı ve 'sg' onarımı
  vodafone.py    hotspot TTL düzeltmesi (ayrı tabloda, eşik korumalı)
  netmon.py      netlink ağ değişikliği izleyicisi
  isps.py        operatör profilleri ve saptama
  tester.py      gerçek bağlantı testleri
  ipc.py         servis ↔ arayüz protokolü
  gui/           GTK4 + libadwaita arayüz
```

---

## Yasal uyarı

Bu araç, ağ üzerinde uygulanan sansürü aşmak için tasarlanmış açık kaynak bir
yazılımdır. Kullanım sorumluluğu tamamen kullanıcıya aittir; bulunduğunuz
ülkenin mevzuatına uymak sizin sorumluluğunuzdadır.

## Lisans

GPL-3.0-or-later — bkz. [LICENSE](LICENSE).
