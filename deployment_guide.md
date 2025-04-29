# Kan Tahlili Uygulaması Deployment Kılavuzu

Bu kılavuz, uygulamanın Render platformunda nasıl ücretsiz olarak deploy edileceğini açıklar.

## Ön Hazırlık

1. [Render.com](https://render.com)'da bir hesap açın (ücretsiz)
2. GitHub veya GitLab hesabınızla bağlanın ya da doğrudan e-posta ile kaydolun

## Render'da Deploy Etme Adımları

### Yöntem 1: GitHub Entegrasyonu ile (Önerilen)

1. Projenizi GitHub'a yükleyin
2. Render Dashboard'a giriş yapın
3. "New +" butonuna tıklayın ve "Web Service" seçin
4. GitHub hesabınızı bağlayın ve kan-tahlil-app reposunu seçin
5. Ayarları yapılandırın:
   - **Name**: kan-tahlil-app
   - **Environment**: Python 3
   - **Region**: Frankfurt (EU) (ya da size en yakın bölge)
   - **Branch**: main
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`
   - **Plan**: Free

6. Aşağıdaki environment variable'ları ekleyin:
   - `GEMINI_API_KEY`: API anahtarınız
   - `STRIPE_API_KEY`: Stripe API anahtarınız (test anahtarı kullanabilirsiniz)
   - `STRIPE_PUBLIC_KEY`: Stripe Public API anahtarınız

7. "Create Web Service" butonuna tıklayın

### Yöntem 2: Manuel Olarak Deploy Etme

1. Render Dashboard'a giriş yapın
2. "New +" butonuna tıklayın ve "Web Service" seçin
3. "Build and deploy from a Git repository" seçeneğini seçin
4. Projenizi manuel olarak yükleyin:
   - `git init`
   - `git add .`
   - `git commit -m "Initial commit"`
   - `git remote add origin <Render_git_url>`
   - `git push origin main`

5. Adım 5-7'yi yukarıdaki gibi tekrarlayın

## Veritabanı Notları

Render'ın ücretsiz planında SQLite veritabanı **geçici** bir dosya sistemi üzerinde çalışır. Bu, uygulamanın yeniden başlatıldığında veritabanının sıfırlanacağı anlamına gelir. Kalıcı veritabanı için:

1. Render'ın PostgreSQL hizmetini kullanın (ücretli)
2. Veya üçüncü taraf bir veritabanı hizmeti kullanın:
   - [ElephantSQL](https://www.elephantsql.com/) (PostgreSQL, ücretsiz plan mevcut)
   - [Supabase](https://supabase.com/) (PostgreSQL, ücretsiz plan mevcut)
   - [MongoDB Atlas](https://www.mongodb.com/cloud/atlas) (MongoDB, ücretsiz plan mevcut)

## Alternatif Deploy Seçenekleri

### PythonAnywhere (Ücretsiz Plan)

1. [PythonAnywhere](https://www.pythonanywhere.com/)'de hesap açın
2. Bir Web app oluşturun
3. Manuel flask kurulumu seçin
4. GitHub'dan kodunuzu klonlayın
5. WSGI dosyasını düzenleyin
6. requirements.txt'deki paketleri yükleyin

### Fly.io (Sınırlı Ücretsiz Kullanım)

1. [Fly.io](https://fly.io/)'da hesap açın
2. flyctl komut satırı aracını yükleyin
3. `flyctl auth login` ile giriş yapın
4. Proje dizininde `flyctl launch` komutunu çalıştırın
5. `fly deploy` ile deploy edin

### Railway (Sınırlı Ücretsiz Kredi)

1. [Railway](https://railway.app/)'de hesap açın
2. GitHub entegrasyonunu kurun
3. New Project > GitHub Repo > kan-tahlil-app reposunu seçin
4. Railway otomatik olarak projeyi build ve deploy eder

## Canlı URL

Deploy işlemi tamamlandıktan sonra, Render size şuna benzer bir URL verecektir:
`https://kan-tahlil-app.onrender.com` 