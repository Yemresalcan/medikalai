#!/bin/bash

# Bu script Fly.io'da uygulamanın ilk kez kurulumunu yapar
# Windows'ta Git Bash ya da WSL ile çalıştırın

echo "MedikalAI uygulamasını Fly.io'ya kurulum başlıyor..."

# Flyctl yüklü mü kontrol et
if ! command -v flyctl &> /dev/null ; then
    echo "Flyctl yüklü değil. Lütfen önce kurulum yapın:"
    echo "curl -L https://fly.io/install.sh | sh"
    exit 1
fi

# Giriş yapın (eğer giriş yapmadıysanız)
echo "Fly.io hesabınıza giriş yapmanız gerekiyor:"
fly auth login

# Doğrudan fly.toml dosyasını kullanarak deploy et (launch kullanmıyoruz)
# Önce API anahtarlarını ekleyelim
echo "Lütfen API anahtarlarınızı girin:"
read -p "GEMINI_API_KEY: " gemini_key
read -p "STRIPE_API_KEY: " stripe_key 
read -p "STRIPE_PUBLIC_KEY: " stripe_public_key

echo "Uygulama oluşturuluyor ve ayarlanıyor..."
# Uygulamayı oluştur ve mevcut fly.toml dosyasını kullan
fly apps create medikalai --json

# API anahtarları ekle
echo "API anahtarları Fly.io'ya ekleniyor..."
fly secrets set GEMINI_API_KEY="$gemini_key" STRIPE_API_KEY="$stripe_key" STRIPE_PUBLIC_KEY="$stripe_public_key"

# Volume oluştur (uygulamadan sonra)
echo "Kalıcı veri için volume oluşturuluyor..."
fly volumes create medikalai_data --size 1 --region fra

# Deploy et - launch yerine direkt deploy kullanıyoruz
echo "Uygulama deploy ediliyor..."
fly deploy --dockerfile scripts/deployment/Dockerfile --strategy immediate

echo "Kurulum tamamlandı! Uygulamanız şu adreste çalışıyor olmalı:"
echo "https://medikalai.fly.dev"
echo ""
echo "Logları kontrol etmek için: fly logs"
echo "Uygulamayı durdurmak için: fly scale count 0"
echo "Uygulamayı başlatmak için: fly scale count 1" 