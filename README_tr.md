# 🏥 MedikalAI - Akıllı Kan Tahlili Analizi

<div align="center">

![Python](https://img.shields.io/badge/python-v3.9+-blue.svg)
![Flask](https://img.shields.io/badge/flask-v2.3.3-green.svg)
![AI](https://img.shields.io/badge/AI-Gemini%202.0-orange.svg)
![License](https://img.shields.io/badge/license-Proprietary-red.svg)
![Status](https://img.shields.io/badge/durum-aktif-success.svg)

**Akıllı sağlık öngörüleri sunan yapay zeka destekli kan tahlili analiz platformu**

[English README](README.md)

</div>

---

## 📖 Proje Hakkında

MedikalAI, kan tahlili sonuçlarını analiz etmek ve kapsamlı sağlık bilgileri sunmak için yapay zekadan yararlanan gelişmiş bir web uygulamasıdır. Flask ile geliştirilen ve Google'ın Gemini AI modeli tarafından desteklenen bu platform, tıp uzmanlarına ve bireylere kan testi parametrelerini ve potansiyel sağlık risklerini anlamaları için sezgisel bir arayüz sunar.

> ⚠️ **Tıbbi Feragatname**: Bu uygulama yalnızca bilgilendirme amaçlıdır ve profesyonel tıbbi tavsiyenin yerini almamalıdır. Doğru teşhis ve tedavi için daima sağlık uzmanlarına danışın.


## 🎯 Temel Özellikler

- **🔬 Yapay Zeka Destekli Analiz**: Gemini 2.0 Flash kullanarak akıllı kan tahlili yorumlama.
- **📄 PDF İşleme**: Kan tahlili PDF'lerinden otomatik veri çıkarma.
- **📊 Kapsamlı Raporlar**: Risk değerlendirmeleri ve öneriler içeren detaylı analizler.
- **🧪 50+ Parametre Desteği**: 8 ana kategoride 50'den fazla kan tahlili parametresi.
- **🔐 Güvenli Kullanıcı Yönetimi**: BCrypt ile şifrelenmiş güvenli kimlik doğrulama.
- **🖥️ Yönetici Paneli**: Kullanıcı ve analiz verilerini yönetmek için özel panel.
- **🎨 Modern Arayüz**: Koyu/Açık tema desteği ile duyarlı tasarım.


## 🛠️ Teknoloji Yığını

**Backend:**
- Python 3.9+, Flask 2.3.3
- Veritabanı: SQLite
- Kimlik Doğrulama: BCrypt, JWT Tokenları

**Yapay Zeka & Veri İşleme:**
- Google Gemini 2.0 Flash API
- PDF İşleme: PyPDF2

**Frontend:**
- Bootstrap 5, JavaScript (ES6+)
- Duyarlı Tasarım (Responsive)

**DevOps:**
- Docker & Docker Compose
- Dağıtım: Fly.io

## 🚀 Kurulum

### Ön Gereksinimler
- Python 3.9 veya üstü
- pip paket yöneticisi
- Git

### Yerel Geliştirme Ortamı

1. **Projeyi klonlayın:**
   ```bash
   git clone https://github.com/Yemresalcan/medikalai.git
   cd medikalai
   ```

2. **Sanal ortam oluşturun ve aktif edin:**
   ```bash
   python -m venv venv
   # Windows için:
   venv\Scripts\activate
   # Linux/Mac için:
   source venv/bin/activate
   ```

3. **Gerekli paketleri yükleyin:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Ortam değişkenlerini ayarlayın:**
   ```bash
   cp .env-example .env
   # .env dosyasını kendi API anahtarlarınızla düzenleyin.
   ```

5. **Veritabanını başlatın:**
   ```bash
   python -c "from app import init_db; init_db()"
   ```

6. **Uygulamayı çalıştırın:**
   ```bash
   python app.py
   ```
   Tarayıcınızda `http://localhost:8080` adresini ziyaret edin.


## ⚠️ ÖNEMLİ YASAL UYARI

Bu yazılım **LİSANSLIDIR** ve açık kaynaklı değildir. Tüm hakları saklıdır. Yazılımın ticari kullanımı, dağıtımı veya değiştirilmesi kesinlikle yasaktır. Yetkisiz kullanım, yasal işlemlere neden olacaktır. Detaylı bilgi için `LICENSE` ve `COPYRIGHT_NOTICE.md` dosyalarını inceleyin.
