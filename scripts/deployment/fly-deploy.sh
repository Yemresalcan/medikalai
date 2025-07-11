#!/bin/bash

# Bu script fly.io'da mevcut uygulamayı kolay bir şekilde deploy etmenizi sağlar
# Windows'ta Git Bash ya da WSL ile çalıştırın

echo "MedikalAI uygulamasını Fly.io'ya deploy ediliyor..."

# Flyctl yüklü mü kontrol et
if ! command -v flyctl &> /dev/null ; then
    echo "Flyctl yüklü değil. Lütfen önce kurulum yapın:"
    echo "curl -L https://fly.io/install.sh | sh"
    exit 1
fi

# Direkt deploy işlemi
echo "Uygulama deploy ediliyor..."
fly deploy --dockerfile scripts/deployment/Dockerfile --strategy immediate

# Durumu kontrol et
echo "Uygulama durumu kontrol ediliyor..."
fly status

echo "Deploy tamamlandı! Uygulamanız şu adreste çalışıyor olmalı:"
echo "https://medikalai.fly.dev"
echo ""
echo "Logları kontrol etmek için: fly logs" 