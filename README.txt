TUGBAYPASS — Windows masaüstü şifre kasası
Sürüm: 1.3.0

BAŞLATMA
TugbayPass-Setup-1.3.0.exe dosyasını çalıştırıp kurulum klasörünü seçin. Windows'un yerleşik .NET Framework derleyicisi eksikse Build-Kasam.cmd ile uygulamayı yeniden oluşturabilirsiniz. İndirme veya ek paket gerekmez. Uygulama simgesi Kasam.ico dosyasıdır; derleme sırasında EXE'ye eklenir.

KASA SEÇİMİ
Kasam, son kullandığınız en fazla 10 kasa dosyasının yolunu bu bilgisayarda hatırlar ve sonraki açılışta en son kullandığınız kasayı otomatik seçip ana parolanızı ister. Kasa seçme penceresiyle uğraşmanız gerekmez. Başka bir kasaya geçmek için uygulamadaki “Kasa seç” düğmesini kullanın; açılış ekranındaki listeden kasayı seçebilir veya farklı bir dosya bulabilirsiniz. Yalnızca dosya yolu hatırlanır; ana parola kaydedilmez. Dosya taşınır ya da silinirse listeden otomatik çıkar.

KULLANIM
Tek bir ana kasa kullanın. Her kayıt eklerken ait olduğu sistemi seçin veya yeni bir sistem adı yazıp “Listeye ekle” düğmesine basın. Sol taraftaki “Sistem” listesinden Google, banka veya eklediğiniz başka bir sisteme geçin; hesap listesi yalnızca seçtiğiniz sistemi gösterir. “Tüm sistemler” seçeneği bütün kayıtları gösterir. Sistemler arasında geçmek için yeni kasa açmanız gerekmez.

Sol listedeki hesaplar çerçeveli kartlar halinde gösterilir. Bir karta tıklayınca kullanıcı adı ve parola ayrıntılarda görünür. “Gizle” düğmesi parolayı tekrar maskeler. Sistem, hesap adı, kullanıcı adı/e-posta, parola, web adresi ve notlar alanlarının yanındaki “Kopyala” düğmeleri ilgili bilgiyi panoya alır.

Sol taraftaki arama alanında hesap adı, sistem, kullanıcı adı/e-posta, parola, web adresi veya notlarda arama yapabilirsiniz.

GÜNCELLEME VE KURULUM
Üst araç çubuğunun altındaki “Güncellemeleri denetle” düğmesi herkese açık TugbayPass deposundaki sürüm bilgisini kontrol eder. Yeni sürüm varsa kurulum dosyasını indirip başlatmayı teklif eder. Güncelleme otomatik ve sessiz kurulmaz; setup penceresinde kurulum konumunu seçebilirsiniz.

TugbayPass-Setup-1.3.0.exe tek dosyalı kurulum aracıdır. Varsayılan konum %LOCALAPPDATA%\Programs\TugbayPass'tır; “Gözat” düğmesiyle farklı klasör seçilebilir. Kurulum başlat menüsü ve isteğe bağlı masaüstü kısayolu oluşturur. Kaldırma işlemi Windows'un “Uygulamalar ve özellikler” bölümünden yapılabilir. Kasa dosyalarınız kurulum klasöründen ayrı tutulur.

GÖRÜNÜM
Arayüz, TugbayPass markasıyla bir yönetim paneli düzeninde tasarlanmıştır. Açık ve koyu tema arasında geçiş yapabilirsiniz; tema seçimi saklanır. Yan menüden sistemi değiştirin, arama alanıyla hesap ve parola arayın, sağ panelden bilgileri görüntüleyin. Araç çubuğu pencere genişliğine uyum sağlar. Uygulama simgesi ve arayüzdeki marka işareti aynı kilit logosunu kullanır.

Değişikliklerden sonra “Kasayı kaydet” düğmesiyle aktif .vault dosyasını güncelleyin. Sonraki açılışlarda dosyayı son kullanılan kasalar listesinden seçebilirsiniz.

ANA PAROLA DEĞİŞTİRME
Kasanız açıkken üstteki “Ana parola” düğmesine basıp yeni ana parolayı iki kez girin. Mevcut kayıtlar yeni anahtarla şifrelenip aynı kasa dosyasına yazılır. Yeni kasa henüz diske kaydedilmediyse parola değişikliği bellekte yapılır; ardından kasayı kaydedin.

YEREL HIZLI AÇILIŞ PIN'İ
Kasa açık ve .vault dosyasına kaydedilmişken “PIN ayarı” düğmesiyle 4 rakamlı PIN belirleyin. Sonraki açılışlarda bu bilgisayardaki aynı Windows hesabında PIN ile açabilirsiniz. PIN yanlış 5 kez girilirse ana parola ekranına geçilir; PIN ekranında “Ana parolayla aç” seçeneği de vardır. PIN, ana parolayı değiştirmez; kasa dosyası ana parola ile güçlü biçimde şifrelenmeye devam eder. Hızlı açılış anahtarı Windows DPAPI ile yalnızca mevcut Windows hesabında korunur. Kasa dosyasını başka bilgisayara veya Windows hesabına taşıdığınızda ana parolayı kullanın. Windows hesabınıza erişebilen zararlı yazılımlara karşı PIN tek başına güvenlik sınırı sayılmaz.

GÜVENLİK
Kayıtlar AES-256-CBC ile şifrelenir ve HMAC-SHA-256 ile doğrulanır. Anahtar, her kasa için rastgele tuz ve PBKDF2-HMAC-SHA-256'nın 600.000 turuyla türetilir. Ana parola unutulursa kasa açılamaz. Kasa dosyanızın güvenli bir yedeğini alın.

UYGUNLUK
Windows 10 veya 11 ve yerleşik .NET Framework 4.7.2 ya da daha yenisi gerekir. Uygulama yalnızca Windows içindir. Tarayıcı uzantısı içermez.