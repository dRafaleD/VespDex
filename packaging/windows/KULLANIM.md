# VespDex Windows x64

ZIP dosyasını yazma iznin olan bir klasöre çıkar. Masaüstü arayüzü için
**Start-VespDex.cmd** dosyasını aç. PowerShell'de aynı klasörden
`./vespdex.exe --gui` ile de açabilirsin. Rust kurulumu gerekmez.
Masaüstü için Direct3D 12 destekli donanım veya Windows yazılım bağdaştırıcısı gerekir.

**ÖRNEK KAYDI AÇ** düğmesiyle yerleşik sentetik örneği aç. Genel Bakış ekranında
4 olay ve 2 süreç görünür. Zaman çizelgesinde DNS sorgusunu seçebilir,
Süreçler ekranında olayları süreç bazında açabilir ve Genel Bakış'tan raporu
yeni bir JSON dosyasına kaydedebilirsin. Komut satırı için
`./vespdex.exe --demo` kullan. Ayrıca **DOSYA SEÇ** ile
`examples/capture.json` dosyasını doğrudan açabilirsin.

Klavye kısayolları: **Ctrl+O** kayıt açar, **Ctrl+F** olay aramasına odaklanır,
**Ctrl+S** raporu kaydeder ve **Esc** süren içe aktarmayı iptal eder.

Sysmon EVTX oluşturma ve canlı gözlem için kayıtların alındığı Windows
ortamında Sysmon yapılandırılmış olmalıdır. Dışa aktarılmış Sysmon EVTX
dosyalarını masaüstünde açmak için yerel Sysmon kurulumu gerekmez. VespDex
örnekleri başlatmaz.

İndirdiğin ZIP'in özetini `Get-FileHash -Algorithm SHA256 <zip>` ile
`SHA256SUMS.txt` içindeki değerle karşılaştır. `PACKAGE-SHA256SUMS.txt`
paketten çıkan dosyaları ayrı ayrı listeler. Bu aday imzasızdır.

Kaldırmak için VespDex'i kapat ve çıkardığın klasörü sil. Saklamak istediğin
raporları önce başka bir klasöre taşı.

## Sorun giderme

- Masaüstü açılmıyorsa başlangıç hatasını görmek için PowerShell'de
  `./vespdex.exe --gui` çalıştır. CLI'yi ayrıca sınamak için
  `./vespdex.exe --demo` kullan.
- EVTX'te seçilecek süreç görünmüyorsa ilgili Sysmon olayının kimliğinin
  1 olduğunu ve `Hashes` alanında SHA-256 bulunduğunu kontrol et. Boyut
  veya süre sınırı hatasında bu süreç başlangıcını da içeren daha kısa bir
  zaman aralığını dışa aktar.
- Dosya zaten var hatası alırsan yeni bir dosya adı seç. Uygulama
  mevcut rapor dosyasını korur.
- ZIP'in SHA-256 değeri farklıysa ZIP'i ve sağlama dosyasını aynı
  sürümden tekrar indir. Uygulamayı açmadan önce değeri yeniden doğrula.
