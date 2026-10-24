# MailDots — Zero-access yol haritası ve gerçek durum

> Bu belge **olduğu gibi** tutulur: kapanmamış hiçbir şey "kapandı" yazılmaz. Durumlar:
> **Açık** (yapılmadı) · **Sürüyor** · **Kapandı — doğrulanmadı** (kod/canlı, bağımsız inceleme yok) ·
> **Kapandı — doğrulandı** (bağımsız inceleme ya da canlı deneme ile, kanıt bağlantılı) · **Kısmen**.
>
> Kaynak: 2026-10-23 yapay zekâ destekli iç güvenlik incelemesi (yalnızca okuma; bağımsız bir firma denetimi değildir). Bulgu numaraları (F1…F18) o rapordan.

## Hedef

"Kayıtlı postanızın **içeriğini** biz bile okuyamayız; istesek de veremeyiz." (Proton'un vaadiyle aynı kapsam.)

Bu vaat **üst veriyi kapsamaz**: konu satırı, gönderen/alıcı, tarih, boyut, IP/bağlantı kayıtları. Bunlar
hem teknik olarak sunucudan geçer hem de yasal saklama yükümlülükleri (ör. 5651) olabilir — avukat
doğrulaması gerekir. Dışarıdan gelen posta sunucuya **düz metin** ulaşır ve kayda geçerken şifrelenir
(Proton'da da aynı).

## Sınır (dürüstçe)

- **Web istemcisi güveni:** webmail kodu bizim sunucumuzdan gelir. Kötü niyetli bir işletmeci değiştirilmiş
  kodla şifreyi/anahtarı çalabilir. Bu tüm web tabanlı E2E hizmetlerde (Proton dahil) yapısaldır; azaltımı
  açık kaynak + imzalı sürüm + bağımsız denetim + kodu sunucudan çekmeyen uygulamadır (T5). Bu kapanana dek
  webmail için "istesek de veremeyiz" **söylenemez**; söylenebilecek en güçlü şey "kayıtlı içeriği okuyamayız".
- **Şifreleme açık olmayan hesaplar** zero-access değildir (T2).

## Proton karşılaştırması — bugünkü gerçek durum

| Konu                     | Proton                                                                               | MailDots                                                                                                                                                                                                                        | Durum                                                        |
| ------------------------ | ------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------ |
| Varsayılan zero-access   | Tüm kutularda varsayılan                                                             | Yeni kutularda varsayılan teklif (bilerek atlanabilir); mevcut müşteri kutuları muaf                                                                                                                                            | Kısmen (T2)                                                  |
| Şifre sunucuya gider mi  | Hayır (SRP)                                                                          | Kasalı hesapta hayır: sunucuya yalnız cihazda türeyen giriş anahtarı (`md1_`) gider ve Stalwart'ta saklanır; şifre ve kasa kilit anahtarı gitmez. **Kötü niyetli sunucu + yeni cihazda ilk giriş** korunmaz (SRP'den farkı bu). | Kısmen (T1.5)                                                |
| Kurtarma                 | Kurtarma ifadesi/dosyası, işletmeci açamaz                                           | Girişsiz kurtarma: 24 kelime + yeni şifre, cihazda; yönetici/panel sıfırlayamaz                                                                                                                                                 | Kapandı — doğrulandı (kod incelemesi); canlı deneme bekliyor |
| Sessiz şifreleme kapatma | Yazılım değişikliğine karşı kriptografik engel yok (aynı sınır); denetim + şeffaflık | Kapatma, zayıflatma ve anahtar değişimi oturumlarda yakalanır, onarılır, bildirilir; örnekleme ve yazılım değişikliği sınırı belgeli                                                                                            | Kapandı, sınırlarla (T3; mobil eksik)                        |
| İmza / bütünlük          | OpenPGP imza + AEAD                                                                  | S/MIME imza (imzala, sonra şifrele); gönderen, alıcılar ve konu imzanın içinde. Şifreleme hâlâ AES-CBC + RSA PKCS#1 v1.5 (AEAD/OAEP yok)                                                                                        | Kısmen (T4)                                                  |
| Anahtar doğrulama        | Adres doğrulama + Key Transparency                                                   | TOFU sabitleme + eklenebilir anahtar günlüğü (zincirli, geriye gidişi yakalar) + imzalı iletide eş tanığı; dış tanık yok                                                                                                        | Kısmen (T4)                                                  |
| Web istemci güveni       | Açık kaynak, bağımsız denetimler                                                     | Kapalı kaynak; zorunlu nonce'lu CSP var, SRI yok, Cloudflare arada                                                                                                                                                              | Kısmen (T5)                                                  |
| Bildirim                 | İçeriksiz tetikleyici (doğrulanmadı)                                                 | Cihaz anahtarıyla mühürlü; Google gönderen/konuyu görmez (yayında)                                                                                                                                                              | Kapandı (T6)                                                 |
| Konu satırı              | E2E değil                                                                            | E2E değil                                                                                                                                                                                                                       | Eşit                                                         |
| IP / günlük              | Varsayılan tutmaz, isteğe bağlı                                                      | Trafik bilgisi 365 gün (5651), teknik günlükler 14 gün, içerik/konu hiç; avukat onayı bekliyor                                                                                                                                  | Kısmen (T7; hukuki farklılık)                                |
| Şeffaflık raporu         | Var                                                                                  | Yok                                                                                                                                                                                                                             | Açık (T8)                                                    |
| Bağımsız denetim         | Var                                                                                  | İç denetim (bu belge)                                                                                                                                                                                                           | Açık (T8)                                                    |

## Görevler

### T1 — Şifre (ya da şifre eşdeğeri) sunucuya asla gitmesin · F2, F3, F15 · **Kısmen**

- [x] **T1.1 — Kapandı — doğrulandı (yapay zekâ destekli kod incelemesi, 2026-10-23).** Korumalı kutuda sunucu düz şifreyi hiçbir rotada posta sunucusuna iletmeden reddeder (giriş, şifre değişimi, kasa işlemleri, posta programları); "derived → password" sessiz düşürme kaldırıldı (giriş ve kasa şifresi yenileme yolu). Kod: `lib/server/keys/protected-secret.ts`, `app/api/auth/login/route.ts`, `lib/server/keys/login-mode.ts`, `lib/server/keys/vault-service.ts`; testler `login-route`, `login-protection`, `vault-slot` (düzeltme geri alınınca kırıldıkları denendi).
      **Zorunlu not:** giriş anahtarı (`md1_`) sunucuya ulaşır ve Stalwart'ta saklanır; ulaşmayan şey şifre ve kasa kilit anahtarıdır. Kötü niyetli sunucuya karşı garanti değildir (T1.5).
- [x] **T1.2 — Kapandı — doğrulandı (yapay zekâ destekli kod incelemesi).** Girişsiz kurtarma: 24 kelime + yeni şifre; anahtar sahipliği RSA-OAEP(SHA-256, etiketli) sınamayla kanıtlanır; sınama tek kullanımlık ve sınama başına (başkası sahibinkini düşüremez); sertifika değişimi ve zayıf KDF cihazda reddedilir; yarım kalırsa kullanıcıya söylenir, ikinci deneme tamamlar. Kod: `lib/server/keys/recovery.ts`, `app/api/auth/recover/*`, `lib/crypto/recovery-client.ts`; test `recovery.test.ts` (ifade, yeni şifre ve özel anahtarın ağa çıkmadığını denetler). Canlı deneme T1.6'da.
- [x] **T1.3 — Kapandı — doğrulandı (canlı deneme, 2026-10-23).** Panel, webmail'de şifre kasası olan kutuda şifre sıfırlamayı reddeder; webmail'e sorulamazsa sıfırlama yapılmaz; Stalwart şifreleme bayrağı ikinci ağ (panel `90f5f03`, webmail iç ucu `9b1d102`). Bizim canlı gözlemimiz (2026-10-23): iç uç dışarıdan 404, imzasız 401, imzalı yanıt doğru. Panel arayüzünden ret denemesi henüz yapılmadı. **Not:** bu bir politika korumasıdır, kriptografik değil — Stalwart yöneticisi şifreyi yine de yazabilir; kazandığı şey şifreli posta ve (webmail düz şifreyi reddettiği için) webmail oturumu değildir.
- [x] **T1.4 — Kapandı — doğrulandı (canlı, 2026-10-23).** Yeni kasa yalnız giriş anahtarıyla açılabilir (`vault-service.ts` `createVault`: `isLoginKey` şartı → hep `switching`→`derived`). Tek eski "password" modlu deneme kasası sahibinin onayıyla kutusuyla birlikte silindi; canlıda kasaların hepsi `derived`. Eski "password" kasa bir daha oluşursa kurtarma ifadesiyle `derived`'e geçebilir; panel onu da sıfırlayamaz.
- [ ] **T1.5 — Kısmen (kalıcı).** Tarayıcı ve uygulama korumalı bildiği hesapta düz şifre göndermez; sunucunun verdiği Argon2id maliyeti tabanın altındaysa (64 MiB / 3 tur) reddedilir (webmail + mobil `f291d3f`). **Yeni cihazda / temizlenmiş tarayıcıda ilk giriş korunmaz**: kötü niyetli sunucu "password" derse şifre gider. Kodla kapanmaz → T4 (anahtar günlüğü dış tanıkla) ya da evrensel derived giriş.
- [ ] **T1.6 — Sürüyor.** Kod incelemesi bitti (yapay zekâ destekli, iki tur, bulgular 1–6 kapandı). Canlı kurtarma denemesi yapıldı (2026-10-23, bir test kutusu: yanlış ifade reddedildi, doğru ifadeyle yeni şifre 18:37 UTC, yeni şifreyle giriş 18:37 UTC, kayıtlı posta şifrelemesi açık kaldı). Eksik: Stalwart'ın `credentials/<id>/secret` değerini özetleyip (hash) özetlemediği — API değeri maskeli döndürüyor, doğrulanamadı. Düz saklıyorsa Stalwart deposunu okuyan biri webmail oturumu açabilir (içeriği çözemez).
- Mobil uygulamada kurtarma ekranı yok (webmail'e yönlendirme gerekir).
- **"Şifremi unuttum" adım adım (2026-10-23):** önce yalnız e-posta; kasalı kutuda 24 kelime cihazda doğrulanır, ancak doğruysa yeni şifre istenir. Kasasız kutuda doğrulanmış kurtarma e-postasına tek kullanımlık bağlantı (30 dk, token URL'nin `#` kısmında, sunucu günlüğüne düşmez) ya da alan adı yöneticisine bildirim; hangisi olduğu söylenmez. Kasalı kutuya bu yoldan hiçbir bağlantı gönderilmez, panel de sıfırlayamaz. Yapay zekâ incelemesi iki tur inceledi; ilk turda 1 yüksek bulgu (silinip yeniden açılan adres eski sahibin kurtarma e-postasını/kasasını devralıyordu) — kapandı: kurtarma e-postası ve kasa posta sunucusundaki hesap kimliğine bağlı, panel kutu silince webmail o adresin verisini temizliyor (hesap sunucuda duruyorsa reddeder, canlıda denendi). Kalan öneri: bağlantıyla sıfırlamada uygulama şifrelerini iptal seçeneği (şimdilik yalnız uyarı).
- maildots.com kutuları panelde kayıtlı olmadığından kurtarma e-postası kullanamaz (panel yalnız kendi alan adlarına posta atar).

### T2 — Şifreleme varsayılan (yeni kutular) · F1 · **Kısmen — yapay zekâ destekli kod incelemesi**

Karar (kullanıcı, 2026-10-24): yeni kutularda **varsayılan teklif**, bilerek atlanabilir; mevcut aktif müşteriler muaf.

- Yeni kutu ilk webmail girişinde tam ekran kurulum ister; "Outlook / iPhone Mail kullanacağım" seçeneği onay kutusuyla bilerek atlanır (`declined`), karar Ayarlar → Güvenlik'te tarihle görünür. Mobil uygulamada kurulum yok; bekleyen kutuya bant gösterir.
- Yayından önce var olan bütün kutular `exempt` listesine alındı (canlıda doğrulandı). Liste alınmadan kimseye sorulmazdı.
- Silinip yeniden açılan adres eski kararı devralmaz (kutu silme temizliği).
- **Zorunlu değildir**; "varsayılan teklif edilir". Açık kalanlar: muaf kutuların göç akışı (eski Outlook kurulumları), tam metin dizininde gövde tutulmadığının doğrulanması (konu tutuluyor — üst veri).

### T3 — Sessiz kapatmayı görünür kıl ve onar · F4 · **Kapandı — doğrulandı (kod incelemesi + canlı deneme), aşağıdaki sınırlarla; mobil eksik**

Canlı deneme (2026-10-23, bir test kutusu): (1) şifreleme sunucuda tamamen kapatıldı (20:07 UTC) → kullanıcı oturum açınca 20:37:40'ta yakalandı, aynı saniyede onarıldı, kırmızı bant çıktı, e-posta gönderildi; (2) yalnız taslak/gönderilen kopya şifrelemesi kapatıldı (20:38) → açık sekme kullanıcı bir şey yapmadan 20:41:34'te yakaladı ve onardı; bildirim sınırı ikinci e-postayı tuttu. Deneme 1, örnekleme sınırını da gösterdi: 30 dakika kapalı kaldı, oturum açılınca fark edildi.

**Kriptografik sınır (dürüstçe):** dışarıdan gelen posta sunucuya düz metin ulaşır ve şifreleme bizim sunucumuzda yapılır. Sunucu YAZILIMINI değiştiren bir işletmeci yeni gelen postanın düz kopyasını tutabilir; bunu aynı sunucuya karşı yapılan hiçbir denetim yakalayamaz ve hiçbir sağlayıcı (Proton dahil) kriptografiyle engelleyemez. Ona karşı savunma T5 (açık kaynak, imzalı istemci) ve T8 (bağımsız denetim).

Yapılan (webmail `d194ca9`…, panel `6d6d3d4`…):

- Ürünümüzde şifrelemeyi kapatan bir yol yok (webmail, panel, uygulama).
- Girişte ve webmail oturumu açıkken 5 dakikada bir (sunucuda dakikada en çok bir kez) canlı ayar okunur: kapalı (`disabled`), başka anahtar — aynı kimlik altında farklı sertifika dahil — (`mismatch`), gönderilen kopya/taslak şifrelemesi kapalı (`weakened`).
- Bulunursa: kasaya ve güvenlik kaydına yazılır, oturumun sırrıyla tam ayar kasanın kendi anahtarına yeniden yazılır (aynı sertifikalı anahtar varsa yeniden kullanılır), kutuya ve alan adının panel sahibine e-posta gider (6 saatte en çok bir), webmail'de kırmızı bant (onarılamadıysa kapatılamaz).
- Kasa etkinleştikten sonra sunucuda şifrelenmeden saklanmış iletiler listede "şifrelenmeden saklandı" rozetiyle görünür.

Sınırlar (yapay zekâ destekli kod incelemesi):

- **Örnekleme:** iki denetim arasında kapatılıp açılırsa ya da hiç oturum açık değilken olursa uyarı çıkmaz; yalnız rozet iz bırakır.
- **Rozet sunucunun beyanına dayanır** (BODYSTRUCTURE, INTERNALDATE): dürüst sunucuda düz saklanmayı gösterir; kötü niyetli sunucu şifreli gösterip düz kopya tutabilir ya da tarihi geriye alabilir.
- **`mismatch` sırasında başka anahtara şifrelenen iletiler işaretlenmez** (şifreli görünürler) ve sahibi onları açamaz.
- E-posta kurcalanan sunucudaki kutuya ve panel sahibine gider; maildots.com gibi panelde olmayan alan adlarında yalnız bant vardır.
- Yönetici işlemlerinin **değiştirilemez** denetim kaydı yok (güvenlik kaydı bizim veritabanımızda) → T8.
- Mobil uygulama denetimi açılışta, yenilemede, hesap değişiminde ve öne gelince yapar (hesap başına en çok dakikada bir); arka planda denetim yok.

### T4 — İmza, bütünlük, anahtar doğrulama · F6, F7 · **Kısmen — yapay zekâ destekli kod incelemesi, 3 tur, bulgular kapatıldı; dış tanık ve canlı iki kullanıcılı deneme yok**

Yapılan (webmail `a151a94`, mobil `8fed174`; 2026-10-24 yayında):

- **İmza:** her şifreli ileti önce gönderenin kendi anahtarıyla S/MIME olarak imzalanır, sonra şifrelenir. İmzanın içinde gönderen, görünür alıcılar (Gizli alıcının kopyasında o alıcı da), konu ve gönderenin gördüğü anahtar günlüğü başı (`X-MailDots-KeyLog`) var. Anahtar kilitliyse ileti imzasız gönderilmez.
- **Hüküm (okurken):** "doğrulandı" yalnızca şunların hepsi tutunca yazar: imza geçerli; sertifika gönderen adresini taşıyor; anahtar dizindeki, bu cihazda sabitlenmiş ve günlükteki anahtarla aynı; imzalı gönderen/konu gösterilenle aynı (tek konu biçimi); bu ileti bana yazılmış. Konu ya da gönderen değişmişse, anahtar farklıysa, günlük geriye gitmiş ya da çatallanmışsa kırmızı uyarı. Eski biçim imza (konu imza dışında) yalnız "gövde imzalı" (sarı). Anahtarı olan biri imzasız gönderdiyse "İmzasız" (sarı).
- **Eklenebilir anahtar günlüğü + eş tanığı:** her anahtar ekleme/kaldırma zincirli (her kayıt öncekinin özetini taşır) bir günlüğe yazılır; istemci günlüğü kendisi doğrular, son başını saklar ve geriye gidişi/yeniden yazılmayı yakalar. Gönderen gördüğü başı imzaya koyar; alıcı kendi gördüğüyle karşılaştırır: farklıysa ya da tam güncel olduğu hâlde gerideyse "günlük uyuşmuyor" (sunucu iki kişiye farklı günlük gösteriyor olabilir). Alıcı anahtarı günlükle uyuşmazsa ileti gönderilmez.

Açık (dürüst sınırlar):

- Bu **tam "anahtar şeffaflığı" değil**: dış/bağımsız tanık yok; çatal yalnız iki kullanıcı imzalı yazışınca yakalanır. Adres özeti tuzsuz SHA-256 — sözlükle adres tahmin edilebilir.
- Şifreleme AES-CBC + RSA PKCS#1 v1.5 (AEAD, RSA-OAEP yok); imza ile şifre çözme aynı anahtar ve sertifikanın keyUsage'ı imzayı açıkça kapsamıyor; imzada sid eşlemesi yapılmıyor.
- Takma adlar "size yazılmış" sayılmıyor (sarı "başkasına imzalanmış" görünebilir). Mobilde "İmzasız" yalnız dizine bakar (webmail yerel günlüğe de bakar).
- Parmak izi karşılaştırma arayüzü (güvenlik numarası) yok.
- Canlı, iki kullanıcılı uçtan uca deneme henüz yapılmadı.

### T5 — İstemci güveni · F5 · **Sürüyor**

- **CSP (zorunlu, 2026-10-24):** her sayfada nonce'lu, `strict-dynamic` içerik güvenliği politikası (`proxy.ts`); Next.js'in 23 betiğinin hepsi nonce'lu. Önce yalnız raporlu çalıştı: tek rapor, bir kütüphanenin yakalanan `Function("")` yetenek denemesiydi. İleti çerçevesinin betiği sayfanın nonce'unu kullanıyor. İhlaller hâlâ `/api/csp-report`'a (yalnız yönerge + kaynak kökeni) yazılıyor.
- **Açık kaynak (2026-10-24):** şifreleme kodu ve Android uygulaması AGPL-3.0 ile yayımlanıyor (geçmişsiz, sır ve iç ayrıntı taraması yapıldı). Şifreleme çekirdeğinin derlemesi tekrarlanabilir: açık kaynaktan derlenen dosyanın özeti uygulamadakiyle aynıdır.
- Açık: SRI / imzalı-yeniden üretilebilir derleme ve istemcide sürüm parmak izi; webmail'in Cloudflare vekilinden çıkarılması (DNS ayarı — kullanıcı); bağımsız denetim (dış firma).
- Masaüstü uygulaması (Windows/macOS) bu güvenin büyük kısmını çözer: kod her girişte sunucudan gelmez (kullanıcı kararı, 2026-10-24: T4–T8 sonrası).

### T6 — Bildirimlerde üst veri · F10 · **Kapandı — yayında (2026-10-24)**

- Her uygulama kurulumu kendi 256 bit anahtarını üretip yalnız bizim sunucumuza verir; sunucu gönderen, konu, hesap ve okunmamış sayısını AES-256-GCM ile mühürler. Firebase (Google) yalnız `type` ve okunamayan bir blob taşır. Anahtarı olmayan eski sürüme içeriksiz bildirim gider (webmail `e3ddd75`, mobil `09ba4f7`; Node'da mühürlenip Android'de açılan ortak test vektörüyle doğrulandı).
- Yayında: yeni uygulama kuruldu, sunucu mühürlü bildirim gönderiyor (test kutusunda cihaz anahtarı kayıtlı görüldü).
- Sınır: bizim sunucumuz içeriği görür (bildirimi o üretir); cihazda son bildirim içeriği düz bir yerel ayarda tutuluyor (T9).

### T7 — Günlük ve yedek diyeti · F12, F13, F14, F16 · **Kapandı — uygulandı (2026-10-24); hukuki süre avukat onayı bekliyor**

İlke: kanunun istediği en az bilgiyi, istediği süre kadar tut; gerisini kısa sürede sil; hiçbir günlükte içerik ya da konu olmasın.

| Kayıt                                       | İçerik                                                    | Süre           | Nasıl    |
| ------------------------------------------- | --------------------------------------------------------- | -------------- | -------- |
| Trafik bilgisi (webmail giriş geçmişi)      | IP, zaman, hesap, tarayıcı                                | 365 gün        | gece işi |
| Güvenlik olayları                           | olay, IP, zaman                                           | 365 gün        | aynı     |
| Panel denetim kaydı                         | kim, ne, IP                                               | 730 gün        | aynı     |
| Tek kullanımlık bağlantı/kodlar             | özet (hash)                                               | süresi dolunca | aynı     |
| nginx erişim günlüğü (posta + web sunucusu) | IP, adres, tarayıcı                                       | 14 gün         | otomatik |
| Posta sunucusu günlüğü                      | IP, gönderen/alıcı adresi (içerik/konu yok)               | 14 gün         | otomatik |
| Sunucu uygulama günlükleri                  | uygulama kayıtları                                        | 14 gün         | otomatik |
| Yedekler (şifreli)                          | veritabanı + ayarlar (posta dahil; E2E kutularda şifreli) | en çok 6 ay    | otomatik |

**Hukuk:** 5651 sayılı Kanun yer sağlayıcıya trafik bilgisini en az 1, en çok 2 yıl saklama yükümlülüğü getirir; 365 gün bu alt sınırdır. MailDots'un sınıfı ve süre **avukatla doğrulanmalıdır** (KVKK saklama-imha politikası da gerekir).
**Sınırlar:** silinen posta yedeklerde en çok 6 ay kalır; sunucuyu ele geçiren biri yedekleri de açabilir; E2E kutuların postası yedekte de şifrelidir. nginx 14 gün tam IP tutar (kötüye kullanım incelemesi için). Webmail Cloudflare arkasında: Cloudflare kendi günlüklerini tutar (T5).

### T8 — Şeffaflık · **Sürüyor — taslak hazır, yayın onayı bekliyor**

- Rapor taslağı: `docs/security/transparency-report.md` (ne okuyabiliriz / okuyamayız, kayıt süreleri, resmî talep politikası ve tablosu, yapılmayanlar).
- Yayımlamak için gereken: şirket yasal adı, dönem talep sayıları (kullanıcıdan), avukat onayı (hukuki metin, içerik/üst veri ayrımı).
- Bağımsız denetim: dış firma gerekir — bizim elimizde değil.
- Yönetici işlemlerinin değiştirilemez kaydı (T3'ten): yok; önerilen yol — günlük özetinin (hash zinciri) herkese açık bir yere düzenli yayımlanması.

### T9 — APPEND şifrelemesi ve mobil sertleştirme · F8, F17 · **Açık**

### T10 — Çeviri özelliği · **Açık** (2026-10-23 yapay zekâ incelemesinde çıktı)

- `app/api/translate` çözülmüş ileti gövdesini sunucuya (ve Google Translate'e) gönderiyor. Şifreli iletide ya engellenmeli ya da açık uyarı/onay istenmeli.

### T11 — Kutu silinip yeniden açılınca eski kasa · **Açık** (düşük)

- Panel kutuyu silince webmail'deki kasa satırı kalıyor; aynı adresle açılan yeni kutu webmail'e giremez (eski ifadeyle kurtarma gerekir). Silmede webmail'e haber verilmeli.

## Değişiklik günlüğü

- 2026-10-23 — Belge oluşturuldu; bütün görevler açık.
- 2026-10-23 — Tek eski biçimli deneme kasası, sahibinin onayıyla silindi. **T1.4 → Kapandı — doğrulandı.**
- 2026-10-23 — T1.3 canlı denendi: panelde şifreli kutunun (bir test kutusu) şifre değişimi reddedildi, denetim kaydında `refused_encrypted`. **T1.3 → Kapandı — doğrulandı (canlı).**
- 2026-10-23 — Adım adım "Şifremi unuttum", kurtarma e-postası, tek kullanımlık bağlantı (webmail `5aedc7d`…`94230f2`, panel `7ba20dc`…`e4ad7ab`); yapay zekâ incelemesi iki tur, karar "canlıda güvenle kalabilir".
- 2026-10-23 — T1: webmail `abe87fb`, `40dd6dd`, `c065c76`, `9b1d102`; panel `d9f967b`, `90f5f03`; mobil `f291d3f`. Yapay zekâ incelemesi iki tur inceledi; ilk turda 6 bulgu (ikisi orta: düz şifre reddedilmeden posta sunucusuna gidiyordu; kasa yenileme yolu sessizce düşürüyordu), ikinci turda hepsi kapandı. Durumlar yukarıda.
