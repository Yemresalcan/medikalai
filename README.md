# MedikalAI - Kan Tahlili Yorumlama Uygulaması

Bu proje, Flask tabanlı bir web uygulaması ile kullanıcılardan kan tahlili dosyalarını alır ve yapay zeka kullanarak tıbbi yorumlama sağlar.

## ✨ Özellikler

- PDF kan tahlili dosyalarını yükleme ve analiz etme
- Gemini AI API ile tıbbi yorumlama
- Kullanıcı yönetimi ve güvenli oturum sistemi
- Stripe entegrasyonu ile abonelik sistemi
- Admin paneli ve kullanıcı yönetimi
- Responsive tasarım ve koyu tema desteği

## 📁 Proje Yapısı

```
medikalai/
├── app.py                    # Ana Flask uygulaması
├── requirements.txt          # Python bağımlılıkları
├── README.md                 # Bu dosya
├── kan_tahlil_app.db        # SQLite veritabanı
├── templates/               # HTML şablonları
├── static/                  # CSS, JS ve görsel dosyalar
└── scripts/
    ├── deployment/          # Deployment dosyaları
    │   ├── Dockerfile       # Docker container yapılandırması
    │   ├── docker-compose.yml
    │   ├── fly.toml         # Fly.io yapılandırması
    │   ├── Makefile         # Yardımcı komutlar
    │   ├── Procfile         # Heroku deployment
    │   └── fly-*.sh         # Fly.io deployment scriptleri
    └── docs/                # Dokümantasyon
        └── deployment_guide.md
```

## 🚀 Yerel Kurulum

### Gereksinimler
- Python 3.9+
- pip

### Adımlar

1. **Gerekli paketleri yükleyin:**
   ```bash
   pip install -r requirements.txt
   ```

2. **API anahtarlarınızı ayarlayın:**
   
   Windows:
   ```cmd
   set GEMINI_API_KEY=your_gemini_api_key
   set STRIPE_API_KEY=your_stripe_api_key
   set STRIPE_PUBLIC_KEY=your_stripe_public_key
   ```
   
   Linux/Mac:
   ```bash
   export GEMINI_API_KEY=your_gemini_api_key
   export STRIPE_API_KEY=your_stripe_api_key
   export STRIPE_PUBLIC_KEY=your_stripe_public_key
   ```

3. **Uygulamayı başlatın:**
   ```bash
   python app.py
   ```

4. **Tarayıcınızda `http://localhost:8080` adresine gidin**

### Varsayılan Admin Hesabı
- Kullanıcı Adı: `admin`
- Şifre: `admin123`

## 🐳 Docker ile Çalıştırma

```bash
cd scripts/deployment
docker-compose up -d
```

## ☁️ Deployment

### Fly.io ile Deployment

1. **Fly.io hesabı oluşturun ve flyctl'yi yükleyin:**
   ```bash
   curl -L https://fly.io/install.sh | sh
   ```

2. **Otomatik kurulum scripti çalıştırın:**
   ```bash
   cd scripts/deployment
   chmod +x fly-setup.sh
   ./fly-setup.sh
   ```

3. **Güncelleme için:**
   ```bash
   chmod +x fly-deploy.sh
   ./fly-deploy.sh
   ```

### Makefile Komutları

```bash
cd scripts/deployment

# Docker işlemleri
make build          # Docker image'ı oluştur
make up             # Konteyneri başlat
make down           # Konteyneri durdur
make logs           # Logları görüntüle

# Fly.io işlemleri  
make fly-deploy     # Fly.io'ya deploy et
make fly-open       # Uygulamayı tarayıcıda aç
make fly-restart    # Uygulamayı yeniden başlat
```

## 🔧 Yapılandırma

### Ortam Değişkenleri

| Değişken | Açıklama | Gerekli |
|----------|----------|---------|
| `GEMINI_API_KEY` | Google Gemini API anahtarı | ✅ |
| `STRIPE_API_KEY` | Stripe API anahtarı | ✅ |
| `STRIPE_PUBLIC_KEY` | Stripe Public API anahtarı | ✅ |
| `DB_PATH` | Veritabanı dosya yolu | ❌ |

### Abonelik Planları

- **Ücretsiz**: Aylık 3 tahlil analizi
- **Temel**: Aylık 10 tahlil analizi (₺49.90)
- **Premium**: Sınırsız tahlil analizi (₺89.90)
- **Aile**: 5 aile üyesi için sınırsız (₺129.90)

## 📖 API Dokümantasyonu

API endpoint'leri JWT token ile korunmaktadır:

- `POST /api/login` - Giriş yapma
- `GET /api/analyses` - Tahlil listesi

## ⚠️ Önemli Notlar

- Bu uygulama **sadece bilgilendirme amaçlıdır**
- Tıbbi tavsiye yerine geçmez
- Kesin tanı için mutlaka doktorunuza danışın
- API anahtarlarınızı güvenli şekilde saklayın

## 🤝 Katkıda Bulunma

1. Projeyi fork edin
2. Feature branch oluşturun (`git checkout -b feature/AmazingFeature`)
3. Değişikliklerinizi commit edin (`git commit -m 'Add some AmazingFeature'`)
4. Branch'inizi push edin (`git push origin feature/AmazingFeature`)
5. Pull Request oluşturun

## 📄 Lisans

Bu proje MIT lisansı altında lisanslanmıştır.

## 📞 İletişim

Sorular veya öneriler için issue açabilirsiniz.
