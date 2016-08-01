ModSecurity

1.  Giriş

Günümüzde internete bağlı kurum veya kuruluşların birçoğu güvenlik
duvarı kullanmaktadır. Kurumlar, güvenlik duvarlarını kurumun iç ağ
güvenliği için veya getirdiği ek özellikler için tercih ederler. Klasik
güvenlik duvarları ip adresi, port numarası, bağlantı durumu gibi bir
paketi OSI katmanında dördüncü seviyeye kadar inceleyerek karar
verirler. Standart güvenlik duvarları OSI katmanının yedinci seviyesinde
çalışmadıklarından web tabanlı ataklara karşı koruma sağlayamazlar. Bazı
güvenlik duvarları yedinci katmana kadar çıkarak belirli protokoller
için inceleme imkanı sunar.

1.  Web Uygulama Güvenlik Duvarı Nedir?

Günümüzde klasik güvenlik duvarları ağa bağlı olan sistemlerin güvenliği
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

1.  ModSecurity Nedir?

ModeSecurity, Trustwave şirketi tarafından geliştirilen açık kaynak
kodlu Apache ile birlikte çalışan (modül olarak) bütünleşik bir web
uygulama güvenlik duvarıdır. Ayrıca Apache’nin mod\_proxy modülü ile
birlikte gateway seviyesinde uygulama güvenlik duvarı vazifesi de
görebilir. Apache sunucusu üzerinde çalıştırdığınız web uygulaması
üzerine kurarak, HTTP trafiğini izleyebilir, gerçek zamanlı analizler
yaparak web uygulamanızın güvenliğini sağlayabilirsiniz. ModSecurity öne
çıkan bazı özellikleri :

1-) İstek filtreleme: Web sunucunuza gelen istekler daha web sunucusunuz
tarafından alınmadan analiz edilir.

2-) Anti-atlatma teknikleri : Gelen url pathleri ve parametleri, analiz
edilmeden önce atlatma tekniklerini önlemek için normalize edilir.

3-) HTTP protokolü: ModSecurity HTTP paketleri üzerinde detaylı seviyede
filtreme yapabilir. Bireysel parametlere veya isimli cookie değerlerini
kontrol edebilirsiniz.

4-) POST veri analizi: ModSecurity POST methodu kullanılarak gelen
istekler içindeki verileri de yakalayabilme gücüne sahiptir.

5-) Denetleme kaydı: Sunucya gelen tüm isteklerin bütün detayları adli
analiz için kullanılabilir.

6-) HTTPS filtreleme: Uygulama katmanında analiz yaptığı için HTTPS
trafiğinin şifresi çözüldükten sonra veride analiz yapmaya başlar.
Böylelikle HTTPS trafiği ile ModSecurity atlayamazsınız.

7-) Dosya kontrolü: Sunucunuza yüklenmiş olan dosyaları kontrol
edebilir.

![](media/image1.png){width="5.38667760279965in"
height="1.4066699475065616in"}

1.  ModSecurity Kurulumu ve Konfigurasyonu

Gereksinimler :

-   Ubuntu / Debian tabanlı işletim sistemi (Örnekte Kali Linux işletim
    sistemi kullanılmıştır.)

-   Yüklenmiş ve konfigure edilmiş bir Apache2 web sunucusu (Kali
    Linuxta kurulmuş bir şekilde gelmektedir.)

Kurulum Aşamaları :

-   İlk olarak modsecurity kurulumunda gerekli olan
    paketler yüklenmelidir.

sudo apt-get install apache2-dev libxml2-dev liblua5.1-0-dev
libcurl4-gnutls-dev libyajl-dev make curl

-   ModSecurity ‘nin en son versiyonu (01.08.2016 tarihi ile 2.9.1
    son versiyondur) indirilip kurulum işlemine başlanabilinir.

mkdir /tmp/modsec && cd /tmp/modsec

wget https://www.modsecurity.org/tarball/2.9.1/modsecurity-2.9.1.tar.gz

tar xvf modsecurity-2.9.1.tar.gz

cd modsecurity-2.9.1

./configure --prefix=/usr/local

make

sudo make install

-   ModSecurity conf dosyası ve ilgili dosyalar, gerekli
    klasörlere kopyalayın.

sudo mkdir /etc/modsecurity

sudo cp
/tmp/modsecstaging/modsecurity-2.9.0/modsecurity.conf-recommended \\
/etc/modsecurity/modsecurity.conf

sudo cp /tmp/modsecstaging/modsecurity-2.9.0/unicode.mapping
/etc/modsecurity

sudo mkdir /var/cache/modsecurity

sudo chown www-data /var/cache/modsecurity

-   /etc/modsecurity/modsecurity.conf dosyası SecAuditLog parametresi
    ModSecurity’nin kurallarına göre alarm ve loglarını basacağı yer
    /var/log/apache2/modsec\_audit.log dizini olarak değiştirin.

-   /etc/apache2/mods-available/ dizini altına security2.load adlı
    dosya oluşturun. Aşağıdaki içeriği bu dosya içine kaydedin.

\# Depends: unique\_id

LoadFile /usr/lib/x86\_64-linux-gnu/libxml2.so.2

LoadModule security2\_module /usr/local/lib/mod\_security2.so

-   /etc/apache2/mods-available/ dizini altına security2.conf adlı
    dosya oluşturun. Aşağıdaki içeriği bu dosya içine kaydedin.

&lt;IfModule security2\_module&gt;

SecDataDir /var/cache/modsecurity

Include /etc/modsecurity/modsecurity.conf

Include
"/usr/local/share/owasp-modsecurity-crs-master/modsecurity\_crs\_10\_setup.conf"

Include
"/usr/local/share/owasp-modsecurity-crs-master/activated\_rules/\*.conf"

&lt;/IfModule&gt;

Bu işlemle beraber ModSecurity’nin kurulum ve konfigürasyonu
sonuçlanmıştır. ModeSecurity bir web uygulama güvenlik duvarıdır. Bu
güvenlik duvarının saldırıları tespit etme ve engellemesi için kurallar
(rules) tanımlamamız gerekmektedir. Bu kural tanımlamaları için bu
dökümanda OWASP ModSecurity Core Rule Set Project’in sunmuş olduğu
saldırı tespit kurallarını kullanacağım. Bunu web sunucunuza kurduğunuz
ModSecurity’e ekleyebilmek için aşağıdaki adımlar kullanılmalıdır.

-   Kurallar dosyası indirilip ModSecurity için gerekli
    dizine kopyalanır.

cd /tmp

wget
https://github.com/SpiderLabs/owasp-modsecurity-crs/archive/master.tar.gz

tar xvf master.tar.gz -C /usr/local/share

cd /usr/local/share/owasp-modsecurity-crs-master

cp modsecurity\_crs\_10\_setup.conf.example
modsecurity\_crs\_10\_setup.conf

-   activated\_rules dizini altında bu kurallar aktivite edilir.

cd activated\_rules

ln -s ../base\_rules/\* .

-   ModSecurity için tanımladığımız modül aktivite edilip apache tekrar
    başlatılarak web uygulama güvenlik duvarımızı
    kullanmaya başlayabiliriz.

a2enmod security2

service apache2 restart

apachectl -M | grep security2 \# çalışan modül göster.

1.  ModSecurity Yapılandırma

ModSecurity yapılandırma direktifleri yapılandırma dosyanıza
(modsecurity.conf) direk olarak eklenir. Apache, yapılandırma
verilerinin birden fazla dosyada bulunmasına izin verdiği için
ModSecurity yapılandırma direktiflerini tek bir dosyada gruplayabilir ya
da birden fazla dosya oluşturabilirsiniz. Bu aynı sunucuda ki iki farklı
web uygulaması için ayrı yapılandırmalar yapmanıza olanak sağlar.
Aşağıda, ModSecurity ana yapılandırılmasında temel bazda yer alması
gereken komutları bulabilirsiniz.

1.  Filtrelemeyi Açma – Kapama

ModSecurity’de varsayılan olarak filtreleme motoru kapalıdır. İstekleri
gizlemek için aşağıdaki komutu modesecurity.conf dosyası içine ekleyin.

SecFilterEngine On

On : Her isteği analiz et.

Off : Hiç birşey yapma.

DynamicOnly : Dinamik olarak üretilen istekleri analiz et.

1.  POST Tarama

HTTP İstek paketinin POST verisini analiz eder. Kullanmak için aşağıdaki
modsecurity.conf dosyasına komutu ekleyin.

SecFilterScanPOST On

ModSecurity POST verisinde iki kodlama tipini destekler.

-   Application/x-www-form-urlencoded : Form verisini iletmek
    için kullanılır.

-   Multipart/form-data : Dosya iletmek için kullanılır.

-   1.  Dinamik Olarak Buffering Durdurma

İstek bazında POST verisi tarama özelliğini kapatabilirsiniz. Karşıdan
dosya yüklemeleri için POST verilerinin taranmasını kapatmak
istiyorsanız aşağıdaki komutu modsecurity.conf dosyanıza ekleyin.

SetEnvIfNoCase Content-Type \\

"\^multipart/form-data;" "MODSEC\_NOPOSTBUFFERING=Do not buffer file
uploads"

1.  Varsayılan İşlem Listesi

Bir istek tanımlanan bir kural ile eşleşmesi durumunda, bir veya daha
fazla işlem uygulanır. Bireysel filtreler kendi işlemlerini içerebilir
ama bütün filtreler için varsayılan bir işlem kümesi tanımlamak daha
kolaydır. Varsayılan işlemleri aşağıdaki komutla tanımlayabilirsiniz.
Aşağıdaki satır her kural eşleşmesinde kayıt tutacak ve isteği 404 durum
kodu ile reddecektir.

SecFilterDefaultAction "deny,log,status:404"

1.  Filtre Kalıtımı

Üst dizinlerde tanımlanan filtreler normal olarak içiçe yazılan Apache
yapılandırma kapsamı tarafından kalıtılırlar. Fakat bu filtremeleri
sitenin bazı bölümlerinde hafifletmek gerekmektedir. Bunun için
aşağıdaki komut kullanılır.

SecFilterInheritance Off

1.  URL Kodlama Denetimi

Özel karakterler URL içerisinde gönderilmeden önce encode edilmelidir.
ModSecurity bu encode edilmiş özel karakterlerin doğru olduklarını
anlmak için kontrol eder. URL kodlama denetimi aşağıdaki şekilde
açılabilir.

SecFilterCheckURLEncoding On

1.  Evrensel Kodlama Denetimi

Eğer uygulamanız veya üzerinde çalıştığı işletim sistemi evrensel kodu
kabul ediyor veya anlıyorsa bu özellik açılmalıdr.

SecFilterCheckUnicodeEncoding On

Bu komut şu durumları kontrol eder : Yetersiz bayt, geçersiz kodlama,
çok uzun karakterler.

1.  Bayt Aralığı Kontrolü

HTTP istekleri içerisindeki baytların sadece belirli bir aralıkta
olmalarını sağlayabilirsiniz. Stackoverflow saldırılarını önlemekte
kullanılabilir.

SecFilterForceByteRange 32 126

1.  Kurallar

Filtreleme motoru çalışır hale getirildiğinde, her gelen istek yakalanır
ve işlemden geçirilmeden önce analiz edilir. Analiz istek formatını
denetlemek için dizay edilen bir seri kontrollerle başlar. Bu kontroller
yapılandırma direktifleri kullanılarak kontrol edilebilir. İkinci
aşamada, isteki kullanıcı tarafından tanımlanan ve eşlenen filtreden
geçer. Bu işlem sonucu başarılı olursa, belli işlemler uygulanır.

1.  Yol (Path) Normalizasyonu

ModSecurity’de istek verileri için filtreler oluşturabilirsiniz.
Filtreler işlenememiş istek verilerine uygulanmaz. Bunu saldırganların
farkedilmemek için kullandıkalrı bir çok değişik atlatma tekniklerini
önlemek için kullanırız. Aşağıdaki komut /bin/sh şeklinde komut satırını
açacak bir dizgi kullanabilir.

SecFilter /bin/sh

1.  Null Bayt Saldırısını Önleme

Null byte saldırıları C/C++ tabanlı yazılımlarınızın dizginin bittiğine
inandırmaya çalışır. Bu tip saldırılar aşağıdaki komutla engellenebilir.

SecFilter hidden

1.  Cookieler

ModSecurity cookiler için tam destek sunar. Sürüm 1 cookie desteği almak
için aşağıdaki komutu girin.

SecFilterCookieFormat 1

1.  ModSecurity Kural Yapısı

ModSecurity’de kendinizde belirli saldırıları tanımlayabilirsiniz.
Tanımlayacağınız bu kuralları SecRule komutu ile “modsecurity.conf”
dosyasına ekleyebilir ya da atak tiplerine göre ayırarakta conf
dosyaları oluşturabilirsiniz.

SecRule
REQUEST\_COOKIES|!REQUEST\_COOKIES:/\_\_utm/|!REQUEST\_COOKIES:/\_pk\_ref/|REQUEST\_COOKIES\_NAMES|ARGS\_NAMES|ARGS|XML:/\*
"(?i:(\\!\\=|\\&\\&|\\|\\||&gt;&gt;|&lt;&lt;|&gt;=|&lt;=|&lt;&gt;|&lt;=&gt;|\\bxor\\b|\\brlike\\b|\\bregexp\\b|\\bisnull\\b)|(?:not\\s+between\\s+0\\s+and)|(?:is\\s+null)|(like\\s+null)|(?:(?:\^|\\W)in\[+\\s\]\*\\(\[\\s\\d\\"\]+\[\^()\]\*\\))|(?:\\bxor\\b|&lt;&gt;|rlike(?:\\s+binary)?)|(?:regexp\\s+binary))"
"phase:2,rev:'2',ver:'OWASP\_CRS/2.2.9',maturity:'9',accuracy:'8',capture,t:none,t:urlDecodeUni,block,msg:'SQL
Injection Attack: SQL Operator Detected',id:'981319',logdata:'Matched
Data: %{TX.0} found within %{MATCHED\_VAR\_NAME}:
%{MATCHED\_VAR}',severity:'2',tag:'OWASP\_CRS/WEB\_ATTACK/SQL\_INJECTION',tag:'WASCTC/WASC-19',tag:'OWASP\_TOP\_10/A1',tag:'OWASP\_AppSensor/CIE1',tag:'PCI/6.5.2',setvar:'tx.msg=%{rule.msg}',setvar:tx.sql\_injection\_score=+%{tx.critical\_anomaly\_score},setvar:tx.anomaly\_score=+%{tx.critical\_anomaly\_score},setvar:tx.%{rule.id}-OWASP\_CRS/WEB\_ATTACK/SQL\_INJECTION-%{matched\_var\_name}=%{tx.0}"

Yukarıda gördüğünüz bu kural web sayfanızdaki input alanına SQL
operatörleri kullanılarak gerçekleştirilmek istenen SQL Injection
saldırılarını önlemektedir. Görüldüğü üzere ModSecurity imzaları yazmak
çok kolay bir iş değildir. Bu neden OWASP’ın CRS Projesi takip
edilebilir. (Link : https://github.com/SpiderLabs/owasp-modsecurity-crs)

1.  Örnek SQL Injection Saldırısı

ModSecurity Web Uygulama Güvenlik Duvarı’nı sunucunuz üzerinde çalışan
Apache Web Sunucusu’na ekledikten sonra doğru çalıştığını aşağıdaki gibi
test edebilirsiniz.

-   SQL Injection saldırısını gerçekleştirebilmem için SQL injection
    zafiyetli bir web uygulamasına ihtiyacınz var. Bunun için Damn
    Vulnerable Web Application uygulamasını (http://www.dvwa.co.uk/)
    kullanabilirsiniz. Aşağıdkai komutları kullanarak hızlı bir şekilde
    kurulumunu yapabilirsiniz.

cd /var/www

git clone https://github.com/RandomStorm/DVWA.git  dvwa

leafpad  dvwa/config/config.inc.php \#password kısmını boş bırakın

Bu işlemleri gerçekleştirdikten sonra sunucunuz içerisinden
http://localhost/dvwa ile uygulamaya ulaşabilirsiniz.

![](media/image2.JPG){width="3.8018864829396324in"
height="4.521026902887139in"}

Daha sonra soldaki menüden SQL injection butonuna tıklayın.

![](media/image3.JPG){width="6.3in" height="5.6097222222222225in"}

User ID input alanına size database versiyonunu verecek aşağıdaki şu sql
komutunu yazın ve submit butonuna tıklayın.

-   %' or 0=0 union select null, version() \#

Aynı zamanda /var/log/apache2/modsec\_audit.log dosyasında logu takip
edin.

![](media/image4.JPG){width="6.3in" height="6.379166666666666in"}

Görüldüğü üzere web sunucusu geriye bir cevap döndürmedi. Log dosyası
üzerinde de bu saldırıyı yakaladığı tespit edilebilmektedir.

![](media/image5.JPG){width="6.3in" height="4.78125in"}

Bu Dvwa uygulamasını kullanarak diğer tipteki saldırlarda hızlı bir
şekilde gerçekleştirilebilir.
