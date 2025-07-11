#!/bin/bash

# Bu script, fly.io'daki uygulamanızı düzeltmek için kullanılabilir
# Windows'ta Powershell veya Git Bash kullanarak çalıştırın

echo "Uygulamayı düzeltmeye başlıyorum..."

# Önce tüm gerekli dosyaların güncel olduğundan emin olun
echo "1. GitHub'a değişiklikleri gönderiyorum..."
git add .
git commit -m "Fix app configuration for Fly.io deployment"
git push

# Uygulamayı yeniden dağıt
echo "2. Uygulamayı yeniden dağıtıyorum..."
fly deploy --dockerfile scripts/deployment/Dockerfile

# Volümleri kontrol et
echo "3. Volümleri kontrol ediyorum..."
fly volumes list

# Secrets'ları kontrol et
echo "4. Secrets'ları kontrol ediyorum... (API anahtarlarının adlarını gösterir, değerlerini değil)"
fly secrets list

# Makineleri yeniden başlat
echo "5. Uygulamayı yeniden başlatıyorum..."
fly apps restart

# Uygulamanın durumunu kontrol et
echo "6. Uygulama durumunu kontrol ediyorum..."
fly status

echo "İşlem tamamlandı. Uygulamanız birkaç dakika içinde erişilebilir olmalıdır: https://medikalai.fly.dev"
echo "Loglarda hata mesajlarını kontrol etmek için: fly logs" 