# VespDex yayın planı

Hedef, Windows x64 üzerinde kurulabilen ve savunma amaçlı dinamik analiz için
kullanılabilen bir VespDex sürüm adayı. AsphDex masaüstünde statik analiz yapar.
Banshee CLI üzerinden göstergeleri işler. VespDex Sysmon kaynaklı kayıtları
davranış zaman çizelgesine ve süreç ilişkilerine dönüştürür. İlk desteklenen canlı
akışta analist gözlemi kendisi başlatır, VespDex kayıtları yetkili Windows analiz
ortamından toplar. Bir olaya ait eksik kayıtlar ekranda açıkça belirtilir.

## Aşamalar ve kabul kanıtı

| Aşama | Teslim | Kabul kanıtı |
| --- | --- | --- |
| 1. Çekirdek ve CI | Rapor sözleşmesini, hatalı girdi sınırlarını ve Windows adaptörünü kapsayan kontroller | Windows ve Linux'ta kilitli bağımlılıklarla derleme, biçim, Clippy ve CLI regresyonları. Windows PowerShell 5.1'de dönüştürücü sözdizimi. |
| 2. Gerçek dinamik analiz | Örnek EVTX, süreç ve alt süreç ilişkileri, canlı Sysmon gözlem aralığı, süre ve çıktı sınırları, anlaşılır hata mesajları | Yetkili bir Windows analiz ortamında zararsız bir örnekle alınan gerçek EVTX ve canlı gözlem. Bilinen süreç, dosya ve seçili ağ olayları raporla karşılaştırılır. Desteklenmeyen veya kayıp olaylar ayrı gösterilir. |
| 3. Masaüstü deneyimi | AsphDex görsel dili, kayıt seçimi, filtrelenebilir zaman çizelgesi, üst/alt süreç görünümü, erişilebilir klavye akışı ve rapor kaydetme | GUI'de normal ve dar pencerede örnek EVTX açılır, odak ve filtreler çalışır, süreç kaynağı görünür, JSON yeniden okunur. Geçersiz kayıt ve iptal akışları da kontrol edilir. |
| 4. Ekosistem | Belgelenmiş v1 sözleşmesi ve geriye uyumluluk, AsphDex'te hash eşleştirme, Banshee'de ağ göstergeleri | Aynı zararsız örneğin VespDex raporu AsphDex'te eşleşir ve farklı hash reddedilir. Banshee aynı rapordan beklenen göstergeleri çıkarır. Entegrasyonların dağıtım durumu ayrı kaydedilir. |
| 5. Dağıtım ve destek | Sürüm numarası, Windows x64 paketi, içerik listesi, SHA-256, Türkçe/İngilizce başlangıç ve sorun giderme, değişiklik geçmişi | Temiz Windows ortamında indirme/kurulum, GUI ve CLI açılışı, demo, rapor kaydetme ve kaldırma doğrulanır. İmzalama durumu ve desteklenen ortamlar paketle açıkça belgelenir. |

## Doğrulama kaydı

- [VespDex 0.3.0-rc.1](https://github.com/dRafaleD/VespDex/releases/tag/v0.3.0-rc.1)
  özel depoda ön sürüm olarak yayımlandı. Sürüm etiketi `d64e343` commit'ine bağlı.
  [Windows ve Linux CI](https://github.com/dRafaleD/VespDex/actions/runs/45349313212)
  ile [ayrı Windows Server 2025 paket kontrolü](https://github.com/dRafaleD/VespDex/actions/runs/45349313638)
  geçti. Temiz çalıştırıcıda GUI `Dx12 / Cpu` ile açıldı. Yayımlanan ZIP,
  sürüm sayfasından yeniden indirildi. SHA-256 ve sekiz paket dosyası
  doğrulandı. Windows 11'de GUI açıldı, CLI dört olay ve iki süreç içeren
  raporu kaydedip yeniden okudu ve geçici çıkarma dizini kaldırıldı.
  Authenticode durumu `NotSigned` olarak doğrulandı. Türkçe ve İngilizce
  paket kılavuzları sorun gidermeyi ve imza durumunu belgeliyor.
  AsphDex ve Banshee entegrasyonları yerel commit'lerde.
- Windows Server 2025 üzerinde [Sysmon kabul çalışması](https://github.com/dRafaleD/VespDex/actions/runs/45054079878)
  (`276b790`) geçti. Gerçek canlı kayıt ve dışa aktarılmış EVTX için kök
  SHA-256, bir alt süreç ve ona ait dosya olayı doğrulandı. Canlı raporda
  gözlem aralığı vardı. Bu senaryo ağ olaylarını ölçmedi.
- Genişletilmiş [Sysmon kabul çalışması](https://github.com/dRafaleD/VespDex/actions/runs/45055070283)
  (`8bc76c8`) geçti. Canlı kayıtta ve EVTX'te kök SHA-256 eşleşti. İki
  raporda da bir loopback bağlantısı, işaret dosyasını oluşturan alt sürece
  ve dinleyicinin portuna bağlandı.
- [Ayrı Windows Server 2025 paket kontrolü](https://github.com/dRafaleD/VespDex/actions/runs/45055348439)
  (`b649e90`) geçti. Arşiv ve sekiz dosyanın SHA-256 değerleri doğrulandı.
  CLI örneği dört olay ve iki süreç üretti. GUI `Dx12 / Cpu` ile açıldı ve
  geçici kurulum klasörü kaldırıldı.
- `0.3.0-rc.1` kaynak adayı `91f62dc` ile sürümlendi. Yerel Windows'ta
  aday ZIP'inden örnek analiz, rapor kaydetme, GUI açılışı ve kaldırma
  geçti. [Aday paket kontrolü](https://github.com/dRafaleD/VespDex/actions/runs/45056216291)
  ve [aday Sysmon kontrolü](https://github.com/dRafaleD/VespDex/actions/runs/45056219745)
  ayrı Windows Server 2025 çalıştırıcılarında geçti. Paket kontrolü sekiz
  dosyayı doğruladı, CLI raporunu yeniden okudu, GUI'yi `Dx12 / Cpu` ile açtı
  ve çıkarılan paketi kaldırdı. Canlı Sysmon ve dışa aktarılmış EVTX birer
  doğru sürece bağlanmış loopback olayı içerdi.
- Adayın [Windows ve Linux CI kontrolü](https://github.com/dRafaleD/VespDex/actions/runs/45056201384)
  geçti. Kilitli bağımlılıklarla biçim, Clippy ve regresyon testleri ile
  Windows PowerShell 5.1 sözdizimi kontrolü çalıştı.
- [Masaüstü kabulü için gerçek EVTX](https://github.com/dRafaleD/VespDex/actions/runs/45056667696)
  (`7eb0636`) ayrı Windows çalıştırıcısında hazırlandı. Dosya yalnızca
  doğrulanmış zararsız kök ve alt sürecin ilgili Sysmon olaylarını içerir.
- Bu EVTX, Sysmon kurulu olmayan Windows'ta yerel sağlayıcı arama hatasını
  ortaya çıkardı. `ff139e4` ile dosya sorgusu düzeltildi. Windows PowerShell
  5.1'de iki seçilebilir süreç, kök SHA-256, alt süreç ilişkisi ve alt sürecin
  dosya ve loopback olayları doğrulandı. Bu düzeltme sürüm adayına dahildir.
  [Ayrı Windows Server 2025 kabul çalışmasında](https://github.com/dRafaleD/VespDex/actions/runs/45347793547)
  canlı Sysmon kontrolü ve Sysmon kurulu olmayan çalıştırıcıda EVTX okuma
  kontrolü geçti.
- Sysmon kurulu olmayan Windows 11 Pro x64'te `ff139e4` masaüstü derlemesiyle
  aynı EVTX normal ve 762 piksel genişliğindeki pencerelerde açıldı. Kök
  seçimi dört olay ve iki süreç gösterdi. Süreç ağacından alt sürece
  geçildiğinde üç olay göründü. `Ctrl+F` arama odağını aldı ve
  `127.0.0.1` filtresi tek ağ olayı bıraktı. `Ctrl+S` ile kaydedilen JSON
  yeniden okunarak üst/alt süreç ve olay ilişkileri doğrulandı. Bozuk EVTX,
  dosya seçicisinden vazgeçme ve çalışan analizi `Esc` ile iptal etme
  senaryolarında önceki rapor ve filtreler korundu.
- `622b1d4` ile güncellenen maske, Windows 11'de hem masaüstü başlangıç
  ekranında hem etkileşimli terminal açılışında görüldü. Bu commit'ten
  yerel olarak hazırlanan Windows x64 ZIP'i sekiz dosyanın sağlama toplamı,
  GUI açılışı, CLI örneği, JSON raporu ve kaldırma kontrollerini geçti.
- Yerel [üç araç uyum kontrolü](BEHAVIOR_REPORT_V1.md#interoperability-check)
  geçti. AsphDex (`a940301`) aynı dosyanın hash'ini eşleştirdi ve farklı
  hash'i reddetti. Banshee (`e68d1b0`) iki ağ göstergesini doğru olay
  sıralarıyla çıkardı. Entegrasyon commit'leri yerel depolarda.
- AsphDex masaüstü dosya girişi, Windows'ta aday VespDex'in gerçekten
  ürettiği raporla izole Electron penceresinde doğrulandı
  (AsphDex `bacab31`, VespDex `91f62dc`). Eşleşen SHA-256 kabul edildi.
  Farklı SHA-256 ve bozuk JSON reddedildi. 680 piksel genişlikte içe
  aktarma düğmesi klavye odağını aldı. Başka bir dosya analiz edildiğinde
  eski davranış özeti temizlendi. Entegrasyon paketi yayımlanmadı.

Gerçek Sysmon kabul kontrolünü, SHA-256, süreç/dosya oluşturma ve loopback ağ kayıtları
etkin bir Windows analiz ortamında çalıştır:

```powershell
cargo build --release --locked
./scripts/verify-sysmon.ps1 -VespDex ./target/release/vespdex.exe
```

Kontrol zararsız bir üst/alt süreç ve geçici işaret dosyası oluşturur. Alt
süreç yalnızca yerel loopback dinleyicisine bağlanır. Canlı kayıttan ve
dışa aktarılmış EVTX'ten kök SHA-256, üst/alt süreç ilişkisi, dosya olayı ve
bağlantının doğru sürece ait olduğunu doğrular. Sysmon ayarlarını değiştirmez.

Her kabul sonucu için commit, ortam, komut ya da kullanıcı akışı, sonuç ve bilinen
sınırlar kaydedilir. Örnek telemetri uydurma veya açıkça zararsız kayıtlardan gelir.
Kullanıcı kayıtları ve gerçek örnekler depoya eklenmez. Kapsam dışındaki olaylar
ve doğrulanmamış platformlar yayın notlarına yazılır.

## Masaüstünde kayıt karşılaştırma

1. İkinci JSON kaydını mevcut rapordan ayrı yükle. Başarısız veya iptal edilen yüklemede açık raporu ve filtreleri koru.
2. İki kaydın hash, gözlem aralığı ve olay sayısı farklarını göster. Yer tutucu hash için dosya kimliğini belirsiz olarak belirt.
3. Sentetik kayıtlarda farklı olay sayılarını ve geçersiz dosya davranışını doğrula.
