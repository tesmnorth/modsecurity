#ModSecurity

##1.  Giriş

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Günümüzde internete bağlı kurum veya kuruluşların birçoğu güvenlik
duvarı kullanmaktadır. Kurumlar, güvenlik duvarlarını kurumun iç ağ
güvenliği için veya getirdiği ek özellikler için tercih ederler. Klasik
güvenlik duvarları ip adresi, port numarası, bağlantı durumu gibi bir
paketi OSI katmanında dördüncü seviyeye kadar inceleyerek karar
verirler. Standart güvenlik duvarları OSI katmanının yedinci seviyesinde
çalışmadıklarından web tabanlı ataklara karşı koruma sağlayamazlar. Bazı
güvenlik duvarları yedinci katmana kadar çıkarak belirli protokoller
için inceleme imkanı sunar.

##1.1  Web Uygulama Güvenlik Duvarı Nedir?

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Günümüzde klasik güvenlik duvarları ağa bağlı olan sistemlerin güvenliği
konusunda artık yeterli olmamaktadır. Bunun sebebi ise geneksel tüm
ataklar OSI katmanının network seviyesinde olduğunu için, network
servisleri hedef alınırdı. Günümüzde ise gereksiz servisler güvenlik
duvarları tarafından kapatılarak, IDS ve IPS sistemleri ile de eski tip
saldırılar büyük oranda engellenebilmektedir. Fakat, gereksiz servisleri
güvenlik duvarları aracılığıyla kapatan kurum veya kuruluşlar, internete
açılan kapıları olan web sunucularını dışarı dünyaya açık tutmak
zorundalar. Böylelikle, saldırganlar açık olan bu web sunucularının açık
olduğu portlar ve üzerinde çalışan uygulamalara saldırmaya yöneldiler.
Hal böyle olunca web uygulamalarına yönelik saldırıları tespit edip
engelleyebilen Web Uygulama Güvenlik Duvarı (WAF) adlı sistemlere
ihtiyaç duyulmaya başlandı. Web Uygulama Güvenlik Duvarı ile belirli
uygulamaların web trafiği izlenebilmekte, zararlı veya tanımlanmış
politikaya uygumayan web trafiği durdurulabilmektedir. Web
uygulamalarını korumak üzere özel olarak tasarlanmış bu ürün ile klasik
güvenlik duvarları, saldırı engelleme sistemleri gibi yazılımlar
tarafından tespit edilmesi mümkün olmayan saldırıların engellenmesine
imkân sağlanmaktadır.

##2.  ModSecurity Nedir?

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ModeSecurity, Trustwave şirketi tarafından geliştirilen açık kaynak
kodlu Apache ile birlikte çalışan (modül olarak) bütünleşik bir web
uygulama güvenlik duvarıdır. Ayrıca Apache’nin mod\_proxy modülü ile
birlikte gateway seviyesinde uygulama güvenlik duvarı vazifesi de
görebilir. Apache sunucusu üzerinde çalıştırdığınız web uygulaması
üzerine kurarak, HTTP trafiğini izleyebilir, gerçek zamanlı analizler
yaparak web uygulamanızın güvenliğini sağlayabilirsiniz. ModSecurity öne
çıkan bazı özellikleri :

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;1-) İstek filtreleme: Web sunucunuza gelen istekler daha web sunucusunuz
tarafından alınmadan analiz edilir.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2-) Anti-atlatma teknikleri : Gelen url pathleri ve parametleri, analiz
edilmeden önce atlatma tekniklerini önlemek için normalize edilir.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3-) HTTP protokolü: ModSecurity HTTP paketleri üzerinde detaylı seviyede
filtreme yapabilir. Bireysel parametlere veya isimli cookie değerlerini
kontrol edebilirsiniz.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4-) POST veri analizi: ModSecurity POST methodu kullanılarak gelen
istekler içindeki verileri de yakalayabilme gücüne sahiptir.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;5-) Denetleme kaydı: Sunucya gelen tüm isteklerin bütün detayları adli
analiz için kullanılabilir.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6-) HTTPS filtreleme: Uygulama katmanında analiz yaptığı için HTTPS
trafiğinin şifresi çözüldükten sonra veride analiz yapmaya başlar.
Böylelikle HTTPS trafiği ile ModSecurity atlayamazsınız.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7-) Dosya kontrolü: Sunucunuza yüklenmiş olan dosyaları kontrol
edebilir.

![alt text](https://github.com/tesmnorth/modsecurity/blob/master/image1.png)

##3.  ModSecurity Kurulumu ve Konfigurasyonu

Gereksinimler :

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   Ubuntu / Debian tabanlı işletim sistemi (Örnekte Kali Linux işletim
    sistemi kullanılmıştır.)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   Yüklenmiş ve konfigure edilmiş bir Apache2 web sunucusu (Kali
    Linuxta kurulmuş bir şekilde gelmektedir.)

Kurulum Aşamaları :

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   İlk olarak modsecurity kurulumunda gerekli olan
    paketler yüklenmelidir.

    sudo apt-get install apache2-dev libxml2-dev liblua5.1-0-dev
    libcurl4-gnutls-dev libyajl-dev make curl

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   ModSecurity ‘nin en son versiyonu (01.08.2016 tarihi ile 2.9.1
    son versiyondur) indirilip kurulum işlemine başlanabilinir.

    mkdir /tmp/modsec && cd /tmp/modsec
    wget https://www.modsecurity.org/tarball/2.9.1/modsecurity-2.9.1.tar.gz
    tar xvf modsecurity-2.9.1.tar.gz
    cd modsecurity-2.9.1
    ./configure --prefix=/usr/local
    make
    sudo make install


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   ModSecurity conf dosyası ve ilgili dosyalar, gerekli
    klasörlere kopyalayın.

    sudo mkdir /etc/modsecurity
    sudo cp /tmp/modsecstaging/modsecurity-2.9.0/modsecurity.conf-recommended \ /etc/modsecurity/modsecurity.conf
    sudo cp /tmp/modsecstaging/modsecurity-2.9.0/unicode.mapping /etc/modsecurity
    sudo mkdir /var/cache/modsecurity
    sudo chown www-data /var/cache/modsecurity


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   /etc/modsecurity/modsecurity.conf dosyası SecAuditLog parametresi
    ModSecurity’nin kurallarına göre alarm ve loglarını basacağı yer
    /var/log/apache2/modsec_audit.log dizini olarak değiştirin.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   /etc/apache2/mods-available/ dizini altına security2.load adlı
    dosya oluşturun. Aşağıdaki içeriği bu dosya içine kaydedin.

    # Depends: unique_id
    LoadFile /usr/lib/x86_64-linux-gnu/libxml2.so.2
    LoadModule security2_module /usr/local/lib/mod_security2.so


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   /etc/apache2/mods-available/ dizini altına security2.conf adlı
    dosya oluşturun. Aşağıdaki içeriği bu dosya içine kaydedin.

    <IfModule security2_module>
        SecDataDir /var/cache/modsecurity
        Include /etc/modsecurity/modsecurity.conf
        Include "/usr/local/share/owasp-modsecurity-crs-master/modsecurity_crs_10_setup.conf"
        Include "/usr/local/share/owasp-modsecurity-crs-master/activated_rules/*.conf"
    </IfModule>


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Bu işlemle beraber ModSecurity’nin kurulum ve konfigürasyonu
sonuçlanmıştır. ModeSecurity bir web uygulama güvenlik duvarıdır. Bu
güvenlik duvarının saldırıları tespit etme ve engellemesi için kurallar
(rules) tanımlamamız gerekmektedir. Bu kural tanımlamaları için bu
dökümanda OWASP ModSecurity Core Rule Set Project’in sunmuş olduğu
saldırı tespit kurallarını kullanacağım. Bunu web sunucunuza kurduğunuz
ModSecurity’e ekleyebilmek için aşağıdaki adımlar kullanılmalıdır.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   Kurallar dosyası indirilip ModSecurity için gerekli
    dizine kopyalanır.

    cd /tmp
    wget https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/master.tar.gz
    tar xvf master.tar.gz -C /usr/local/share
    cd /usr/local/share/owasp-modsecurity-crs-master
    cp modsecurity_crs_10_setup.conf.example modsecurity_crs_10_setup.conf


&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   activated\_rules dizini altında bu kurallar aktivite edilir.

    cd activated_rules
    ln -s ../base_rules/* .

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   ModSecurity için tanımladığımız modül aktivite edilip apache tekrar
    başlatılarak web uygulama güvenlik duvarımızı
    kullanmaya başlayabiliriz.

    a2enmod security2
    service apache2 restart
    apachectl -M | grep security2 # çalışan modül göster.

##4.  ModSecurity Yapılandırma

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ModSecurity yapılandırma direktifleri yapılandırma dosyanıza
(modsecurity.conf) direk olarak eklenir. Apache, yapılandırma
verilerinin birden fazla dosyada bulunmasına izin verdiği için
ModSecurity yapılandırma direktiflerini tek bir dosyada gruplayabilir ya
da birden fazla dosya oluşturabilirsiniz. Bu aynı sunucuda ki iki farklı
web uygulaması için ayrı yapılandırmalar yapmanıza olanak sağlar.
Aşağıda, ModSecurity ana yapılandırılmasında temel bazda yer alması
gereken komutları bulabilirsiniz.

##4.1  Filtrelemeyi Açma – Kapama

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ModSecurity’de varsayılan olarak filtreleme motoru kapalıdır. İstekleri
gizlemek için aşağıdaki komutu modesecurity.conf dosyası içine ekleyin.

    SecFilterEngine On

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;On : Her isteği analiz et.
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Off : Hiç birşey yapma.
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;DynamicOnly : Dinamik olarak üretilen istekleri analiz et.

##4.2  POST Tarama

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HTTP İstek paketinin POST verisini analiz eder. Kullanmak için aşağıdaki
modsecurity.conf dosyasına komutu ekleyin.

    SecFilterScanPOST On

ModSecurity POST verisinde iki kodlama tipini destekler.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   Application/x-www-form-urlencoded : Form verisini iletmek için kullanılır.
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   Multipart/form-data : Dosya iletmek için kullanılır.

##4.3  Dinamik Olarak Buffering Durdurma

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;İstek bazında POST verisi tarama özelliğini kapatabilirsiniz. Karşıdan
dosya yüklemeleri için POST verilerinin taranmasını kapatmak
istiyorsanız aşağıdaki komutu modsecurity.conf dosyanıza ekleyin.

    SetEnvIfNoCase Content-Type \
    "^multipart/form-data;" "MODSEC_NOPOSTBUFFERING=Do not buffer file uploads"


##4.4  Varsayılan İşlem Listesi

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Bir istek tanımlanan bir kural ile eşleşmesi durumunda, bir veya daha
fazla işlem uygulanır. Bireysel filtreler kendi işlemlerini içerebilir
ama bütün filtreler için varsayılan bir işlem kümesi tanımlamak daha
kolaydır. Varsayılan işlemleri aşağıdaki komutla tanımlayabilirsiniz.
Aşağıdaki satır her kural eşleşmesinde kayıt tutacak ve isteği 404 durum
kodu ile reddecektir.

    SecFilterDefaultAction "deny,log,status:404"

##4.5  Filtre Kalıtımı

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Üst dizinlerde tanımlanan filtreler normal olarak içiçe yazılan Apache
yapılandırma kapsamı tarafından kalıtılırlar. Fakat bu filtremeleri
sitenin bazı bölümlerinde hafifletmek gerekmektedir. Bunun için
aşağıdaki komut kullanılır.

    SecFilterInheritance Off

##4.6  URL Kodlama Denetimi

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Özel karakterler URL içerisinde gönderilmeden önce encode edilmelidir.
ModSecurity bu encode edilmiş özel karakterlerin doğru olduklarını
anlmak için kontrol eder. URL kodlama denetimi aşağıdaki şekilde
açılabilir.

    SecFilterCheckURLEncoding On

##4.7  Evrensel Kodlama Denetimi

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Eğer uygulamanız veya üzerinde çalıştığı işletim sistemi evrensel kodu
kabul ediyor veya anlıyorsa bu özellik açılmalıdr.

    SecFilterCheckUnicodeEncoding On

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Bu komut şu durumları kontrol eder : Yetersiz bayt, geçersiz kodlama,
çok uzun karakterler.

##4.8  Bayt Aralığı Kontrolü

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;HTTP istekleri içerisindeki baytların sadece belirli bir aralıkta
olmalarını sağlayabilirsiniz. Stackoverflow saldırılarını önlemekte
kullanılabilir.

    SecFilterForceByteRange 32 126

##4.9  Kurallar

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Filtreleme motoru çalışır hale getirildiğinde, her gelen istek yakalanır
ve işlemden geçirilmeden önce analiz edilir. Analiz istek formatını
denetlemek için dizay edilen bir seri kontrollerle başlar. Bu kontroller
yapılandırma direktifleri kullanılarak kontrol edilebilir. İkinci
aşamada, isteki kullanıcı tarafından tanımlanan ve eşlenen filtreden
geçer. Bu işlem sonucu başarılı olursa, belli işlemler uygulanır.

##4.10  Yol (Path) Normalizasyonu

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ModSecurity’de istek verileri için filtreler oluşturabilirsiniz.
Filtreler işlenememiş istek verilerine uygulanmaz. Bunu saldırganların
farkedilmemek için kullandıkalrı bir çok değişik atlatma tekniklerini
önlemek için kullanırız. Aşağıdaki komut /bin/sh şeklinde komut satırını
açacak bir dizgi kullanabilir.

    SecFilter /bin/sh

##4.11  Null Bayt Saldırısını Önleme

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Null byte saldırıları C/C++ tabanlı yazılımlarınızın dizginin bittiğine
inandırmaya çalışır. Bu tip saldırılar aşağıdaki komutla engellenebilir.

    SecFilter hidden

##4.12  Cookieler

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ModSecurity cookiler için tam destek sunar. Sürüm 1 cookie desteği almak
için aşağıdaki komutu girin.

    SecFilterCookieFormat 1

##5.  ModSecurity Kural Yapısı

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ModSecurity’de kendinizde belirli saldırıları tanımlayabilirsiniz.
Tanımlayacağınız bu kuralları SecRule komutu ile “modsecurity.conf”
dosyasına ekleyebilir ya da atak tiplerine göre ayırarakta conf
dosyaları oluşturabilirsiniz.

    SecRule REQUEST_COOKIES|!REQUEST_COOKIES:/__utm/|!REQUEST_COOKIES:/_pk_ref/|REQUEST_COOKIES_NAMES|ARGS_NAMES|ARGS|XML:/* "(?i:(\!\=|\&\&|\|\||>>|<<|>=|<=|<>|<=>|\bxor\b|\brlike\b|\bregexp\b|\bisnull\b)|(?:not\s+between\s+0\s+and)|(?:is\s+null)|(like\s+null)|(?:(?:^|\W)in[+\s]*\([\s\d\"]+[^()]*\))|(?:\bxor\b|<>|rlike(?:\s+binary)?)|(?:regexp\s+binary))" "phase:2,rev:'2',ver:'OWASP_CRS/2.2.9',maturity:'9',accuracy:'8',capture,t:none,t:urlDecodeUni,block,msg:'SQL Injection Attack: SQL Operator Detected',id:'981319',logdata:'Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}',severity:'2',tag:'OWASP_CRS/WEB_ATTACK/SQL_INJECTION',tag:'WASCTC/WASC-19',tag:'OWASP_TOP_10/A1',tag:'OWASP_AppSensor/CIE1',tag:'PCI/6.5.2',setvar:'tx.msg=%{rule.msg}',setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score},setvar:tx.anomaly_score=+%{tx.critical_anomaly_score},setvar:tx.%{rule.id}-OWASP_CRS/WEB_ATTACK/SQL_INJECTION-%{matched_var_name}=%{tx.0}"

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Yukarıda gördüğünüz bu kural web sayfanızdaki input alanına SQL
operatörleri kullanılarak gerçekleştirilmek istenen SQL Injection
saldırılarını önlemektedir. Görüldüğü üzere ModSecurity imzaları yazmak
çok kolay bir iş değildir. Bu neden OWASP’ın CRS Projesi takip
edilebilir. (Link : https://github.com/SpiderLabs/owasp-modsecurity-crs)

##6.  Örnek SQL Injection Saldırısı

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;ModSecurity Web Uygulama Güvenlik Duvarı’nı sunucunuz üzerinde çalışan
Apache Web Sunucusu’na ekledikten sonra doğru çalıştığını aşağıdaki gibi
test edebilirsiniz.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   SQL Injection saldırısını gerçekleştirebilmem için SQL injection
    zafiyetli bir web uygulamasına ihtiyacınz var. Bunun için Damn
    Vulnerable Web Application uygulamasını (http://www.dvwa.co.uk/)
    kullanabilirsiniz. Aşağıdkai komutları kullanarak hızlı bir şekilde
    kurulumunu yapabilirsiniz.

    cd /var/www
    git clone https://github.com/RandomStorm/DVWA.git  dvwa
    leafpad dvwa/config/config.inc.php #password kısmını boş bırakın

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Bu işlemleri gerçekleştirdikten sonra sunucunuz içerisinden http://localhost/dvwa ile uygulamaya ulaşabilirsiniz.

![alt text](https://github.com/tesmnorth/modsecurity/blob/master/image2.png)

Daha sonra soldaki menüden SQL injection butonuna tıklayın.

![alt text](https://github.com/tesmnorth/modsecurity/blob/master/image3.png)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;User ID input alanına size database versiyonunu verecek aşağıdaki şu sql
komutunu yazın ve submit butonuna tıklayın.

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;-   %' or 0=0 union select null, version() #

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Aynı zamanda /var/log/apache2/modsec_audit.log dosyasında logu takip edin.

![alt text](https://github.com/tesmnorth/modsecurity/blob/master/image4.png)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Görüldüğü üzere web sunucusu geriye bir cevap döndürmedi. Log dosyası
üzerinde de bu saldırıyı yakaladığı tespit edilebilmektedir.

![alt text](https://github.com/tesmnorth/modsecurity/blob/master/image5.png)

&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Bu Dvwa uygulamasını kullanarak diğer tipteki saldırlarda hızlı bir
şekilde gerçekleştirilebilir.

