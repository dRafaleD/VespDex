# VespDex Windows x64

ZIP dosyasını yazma iznin olan bir klasöre çıkar. Masaüstü arayüzü için
**Start-VespDex.cmd** dosyasını aç. PowerShell'de aynı klasörden
`./vespdex.exe --gui` ile de açabilirsin. Rust kurulumu gerekmez.

DOSYA SEÇ ile `examples/capture.json` dosyasını aç. Genel Bakış ekranında
4 olay ve 2 süreç görünür. Zaman çizelgesinde DNS sorgusunu seçebilir,
Süreçler ekranında olayları süreç bazında açabilir ve Genel Bakış'tan raporu
yeni bir JSON dosyasına kaydedebilirsin. Komut satırı için
`./vespdex.exe ./examples/capture.json` kullan.

Sysmon EVTX oluşturma ve canlı gözlem için kayıtların alındığı Windows
ortamında Sysmon yapılandırılmış olmalıdır. VespDex örnekleri başlatmaz.

İndirdiğin ZIP'in özetini `Get-FileHash -Algorithm SHA256 <zip>` ile
`SHA256SUMS.txt` içindeki değerle karşılaştır. `PACKAGE-SHA256SUMS.txt`
paketten çıkan dosyaları ayrı ayrı listeler. Bu aday imzasızdır.

Kaldırmak için VespDex'i kapat ve çıkardığın klasörü sil. Saklamak istediğin
raporları önce başka bir klasöre taşı.
