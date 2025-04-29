# PythonAnywhere Deployment Kılavuzu - Kan Tahlil Uygulaması

Bu kılavuz, kan tahlil uygulamanızı PythonAnywhere'de ücretsiz olarak deploy etme adımlarını açıklamaktadır.

## Adım 1: PythonAnywhere'de Hesap Oluşturma

1. [PythonAnywhere](https://www.pythonanywhere.com/) adresine gidin ve ücretsiz bir hesap oluşturun
2. Kayıt olduktan sonra hesabınıza giriş yapın ve kontrol paneline ulaşın

## Adım 2: Kodunuzu Yükleme

### Manuel Yükleme (Önerilen)
1. Projenizi ZIP olarak bilgisayarınızda sıkıştırın
2. PythonAnywhere'de "Files" sekmesine gidin
3. "Upload a file" ile ZIP dosyanızı yükleyin
4. Bash konsolunda dosyayı çıkartın:
   ```bash
   unzip kan-tahlil-app.zip -d kan-tahlil-app
   cd kan-tahlil-app
   ```

### GitHub'dan Klonlama
Eğer kodunuz GitHub'da ise:
1. PythonAnywhere'de "Consoles" sekmesine gidin ve "Bash" konsolu açın
2. GitHub reponuzu klonlayın:
   ```bash
   git clone https://github.com/kullanıcıadınız/kan-tahlil-app.git
   ```

## Adım 3: Sanal Ortam Oluşturma ve Paketleri Yükleme

1. Bash konsolunda projenizdeki dizine gidin:
   ```bash
   cd kan-tahlil-app
   ```

2. Sanal ortamı oluşturun:
   ```bash
   mkvirtualenv --python=/usr/bin/python3.9 kan-tahlil-env
   ```

3. Sanal ortamı aktifleştirin (eğer otomatik aktifleşmediyse):
   ```bash
   workon kan-tahlil-env
   ```

4. Gereksinimleri yükleyin:
   ```bash
   pip install -r requirements.txt
   ```

## Adım 4: Web Uygulaması Oluşturma

1. PythonAnywhere'de "Web" sekmesine gidin
2. "Add a new web app" butonuna tıklayın
3. Domainini onaylayın (örn. `kullaniciadi.pythonanywhere.com`)
4. "Manual configuration" seçeneğini seçin
5. Python sürümünüzü seçin (Python 3.9)

## Adım 5: WSGI Dosyasını Yapılandırma

1. Web sekmesinde, WSGI dosyasının (örn. `/var/www/kullaniciadi_pythonanywhere_com_wsgi.py`) bağlantısına tıklayın
2. Dosyayı şu şekilde düzenleyin:

```python
import sys
import os

# Proje dizinini belirtin
path = '/home/kullaniciadi/kan-tahlil-app'
if path not in sys.path:
    sys.path.append(path)

# Sanal ortam dizinini belirtin
os.environ['VIRTUAL_ENV'] = '/home/kullaniciadi/.virtualenvs/kan-tahlil-env'
os.environ['PATH'] = '/home/kullaniciadi/.virtualenvs/kan-tahlil-env/bin:' + os.environ['PATH']

# İhtiyaç duyulan çevre değişkenlerini ekleyin
os.environ['GEMINI_API_KEY'] = 'sizin_api_anahtarınız'
os.environ['STRIPE_API_KEY'] = 'stripe_api_anahtarınız'
os.environ['STRIPE_PUBLIC_KEY'] = 'stripe_public_anahtarınız'

# Flask uygulamanızı içe aktarın
from app import app as application
```

3. Değişiklikleri kaydedin

## Adım 6: Statik Dosyaları Yapılandırma

1. Web sekmesinde, "Static files" bölümüne gidin
2. Yeni statik dosya yapılandırmaları ekleyin:
   - URL: `/static/`
   - Directory: `/home/kullaniciadi/kan-tahlil-app/static/`

## Adım 7: Web Uygulamasını Yeniden Başlatma

1. Web sekmesine geri dönün
2. "Reload" butonuna tıklayın
3. Uygulamanızı `kullaniciadi.pythonanywhere.com` adresinde görüntüleyin

## Veritabanı Notları

PythonAnywhere ücretsiz planda SQLite veritabanını destekler ve verileriniz kalıcı olarak saklanır. Aşağıdaki adımları izleyin:

1. Bash konsolunda SQLite veritabanını oluşturun:
   ```bash
   cd ~/kan-tahlil-app
   python
   >>> from app import app, init_db
   >>> with app.app_context():
   ...     init_db()
   >>> exit()
   ```

2. Bu işlem veritabanınızı ve tablolarınızı oluşturacaktır.

## PythonAnywhere Ücretsiz Plan Limitleri ve Avantajları

PythonAnywhere ücretsiz planda şunları sunar:
- 512MB disk alanı
- Düşük CPU ve RAM
- Sınırlı sayıda web uygulaması (1 adet)
- pythonanywhere.com alt alan adı
- Always-on web uygulaması (sürekli çalışır, haftalık restart gerekir)
- SSL sertifikası

## Sorun Giderme

- **ModuleNotFoundError**: Sanal ortamda eksik modüller varsa:
  ```bash
  workon kan-tahlil-env
  pip install <eksik_modul>
  ```

- **Permission Error**: Dosya izinleri hatası için:
  ```bash
  chmod +x /home/kullaniciadi/kan-tahlil-app/app.py
  ```

- **Internal Server Error**: WSGI dosyasında hata olabilir, logları kontrol edin:
  - "Web" sekmesinde "Log files" bölümüne bakın
  - "Error log" dosyasını kontrol edin

## İletişim

Herhangi bir sorun yaşarsanız, PythonAnywhere'in [dokümantasyonu](https://help.pythonanywhere.com/) size yardımcı olabilir. 