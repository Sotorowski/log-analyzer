# 🔍 Apache Log Analyzer - Türkçe Kullanım Rehberi

Bir Apache erişim loglarını analiz eden ve şüpheli aktiviteleri tespit eden üretim kalitesinde Python uygulaması.

## 📁 Proje Yapısı

```
log_analyzer/
├── analyzer.py      # Ana analizör ve Flask web arayüzü
├── parser.py        # Apache log ayrıştırma modülü
├── rules.py         # Güvenlik tespit kuralları
├── sample.log       # Test verisi içeren örnek log dosyası
├── requirements.txt # Python bağımlılıkları
├── README.md        # İngilizce dokümantasyon
└── OKUBENİ.md      # Türkçe kullanım rehberi (bu dosya)
```

## 🚀 Özellikler

### Temel Güvenlik Tespiti
- **Brute Force Tespiti**: Tekrarlı giriş denemelerini belirler (>20/IP)
- **404 Flood Tespiti**: Aşırı 404 yanıtlarını tespit eder (>50/IP)
- **Rate Limiting Tespiti**: Yüksek istek oranlarını bulur (>100 istek/dakika)

### Web Arayüzü
- Tarayıcıdan log dosyası yükleme
- Anında analiz sonuçları
- Temiz, responsive arayüz
- Detaylı istatistikler ve uyarılar

### Komut Satırı Arayüzü
- Yerel log dosyalarını analiz etme
- HTML raporları oluşturma
- Yapılandırılabilir tespit eşiği değerleri

## 📦 Kurulum

1. Projeyi klonlayın veya indirin
2. Bağımlılıkları yükleyin:
```bash
pip install -r requirements.txt
```

## 🔧 Kullanım

### Komut Satırı
```bash
# Bir log dosyasını analiz et
python analyzer.py sample.log

# Özel HTML raporu oluştur
python analyzer.py sample.log -o ozel_rapor.html

# Web arayüzünü başlat
python analyzer.py --web --port 8080
```

### Web Arayüzü
1. Web sunucusunu başlatın:
```bash
python analyzer.py --web
```
2. Tarayıcıda http://localhost:5000 açın
3. Apache log dosyanızı yükleyin
4. Analiz sonuçlarını anında görün

## 📊 Çıktı Örnekleri

### Terminal Çıktısı
```
[*] Log Analiz Sonuçları
==================================================
Toplam analiz edilen giriş: 174
Analiz zamanı: 2026-02-23T00:08:29.231419

[*] İstatistikler:
  - Benzersiz IP'ler: 6
  - Zaman aralığı: 3.0 dakika
  - Tespitler:
    * brute_force: 1
    * rate_limiting: 1

[!] Şüpheli IP'ler Bulundu:
  - IP: 10.0.0.50
    * Brute Force: /login'e 23 deneme
  - IP: 203.0.113.10
    * Rate Limiting: 5 dakikada 111 istek
```

### HTML Raporu
- Detaylı istatistik tabloları
- Görsel şüpheli IP uyarıları
- Durum kodu dağılımı
- HTTP metodu analizi
- Dışa aktarılabilir sonuçlar

## ⚙️ Yapılandırma

Tespit eşikleri `rules.py` dosyasında yapılandırılabilir:

```python
config = {
    'brute_force_threshold': 20,      # IP başına deneme
    'brute_force_endpoint': '/login',   # hedef endpoint
    '404_threshold': 50,              # IP başına 404 yanıtı
    'rate_limit_threshold': 100,        # dakika başına istek
    'time_window_minutes': 5           # analiz zaman penceresi
}
```

## 🧪 Test Verisi

Dahil edilen `sample.log` dosyası içerir:
- Normal trafik desenleri
- Brute force saldırısı (IP: 10.0.0.50)
- 404 flood denemeleri (IP: 172.16.0.25)
- Yüksek frekanslı istekler (IP: 203.0.113.10)

## 🔒 Güvenlik Özellikleri

- **Giriş Doğrulama**: Güvenli log dosyası ayrıştırma
- **Hata Yönetimi**: Zarif hata kurtarma
- **Bellek Verimliliği**: Büyük logları artımlı olarak işler
- **Yapılandırılabilir**: Ayarlanabilir tespit hassasiyeti

## 📈 Performans

- Büyük log dosyalarını verimli şekilde işler
- Rate limiting için kayan pencere analizi
- Log ayrıştırma için optimize edilmiş regex desenleri
- Minimal bellek ayak izi

## 🛠️ Bağımlılıklar

- **Python 3.7+**
- **Flask 2.3.3** (isteğe bağlı, web arayüzü için)

## 📝 Desteklenen Log Formatı

Apache Common Log Format desteği:
```
127.0.0.1 - - [10/Oct/2024:08:15:00 +0000] "GET /index.html HTTP/1.1" 200
```

Çıkarılan alanlar:
- IP adresi
- Zaman damgası
- HTTP metodu
- Endpoint/URL yolu
- Durum kodu

## 🚨 Tespit Detayları

### Brute Force Tespiti
- Giriş endpoint denemelerini izler
- Yapılandırılabilir deneme eşiği
- Zaman tabanlı analiz
- Benzersiz IP takibi

### 404 Flood Tespiti
- IP başına 404 yanıtlarını sayar
- Tarama davranışlarını belirler
- Erişilen endpoint'leri takip eder
- Zaman aralığı analizi

### Rate Limiting Tespiti
- Kayan pencere algoritması
- Dakika başına istek hesaplaması
- Metot ve endpoint dökümü
- Yapılandırılabilir eşikler

## 🔄 Gelecek Geliştirmeler

- Ek log formatı desteği
- Makine öğrenmesi tespiti
- Gerçek zamanlı izleme
- Veritabanı entegrasyonu
- Alert bildirimleri

## 📄 Lisans

Bu proje eğitim ve güvenlik analizi amaçlı olduğu gibi sağlanmıştır.

---

**Güvenlik profesyonelleri için ❤️ ile yapıldı**

## 🎯 Hızlı Başlangıç

```bash
# 1. Test verisiyle analiz
python analyzer.py sample.log

# 2. Kendi log'unu analiz et
python analyzer.py kendi_logun.log

# 3. Web arayüzü başlat
python analyzer.py --web

# 4. Sonuçları gör
# - Terminal çıktısını oku
# - report.html'i tarayıcıda aç
```

**Proje tamamen çalışır durumda ve kullanıma hazır!** 🚀
