#!/bin/bash

# Bu script, Fly.io'daki API bölge kısıtlaması sorunlarını çözmek için kullanılır

# 1. Önceki dağıtımları kontrol et
echo "Mevcut dağıtımlar kontrol ediliyor..."
fly status

# 2. Bölge değişiklikleri
echo "Bölge değişiklikleri yapılıyor..."
echo "Önerilen bölgeler: ams (Amsterdam), sin (Singapur), syd (Sidney), fra (Frankfurt)"

# Kullanıcının bölge seçimi
read -p "Kullanmak istediğiniz bölgeyi girin (örn: ams, fra, sin, syd): " REGION

# fly.toml dosyasını güncelle
sed -i "s/primary_region = \".*\"/primary_region = \"$REGION\"/" fly.toml
echo "fly.toml dosyası güncellendi: Bölge $REGION olarak ayarlandı"

# 3. Ortam değişkenlerini ayarla
echo "API bölge değişkenleri ayarlanıyor..."
fly secrets set API_REGION=global API_USE_PROXY=false

# 4. Uygulamayı yeniden başlat
echo "Uygulama yeniden başlatılıyor..."
fly deploy --no-cache

# 5. Proxy kullanımını etkinleştir (isteğe bağlı)
read -p "Proxy kullanmak istiyor musunuz? (evet/hayır): " USE_PROXY

if [ "$USE_PROXY" = "evet" ]; then
    echo "Proxy kullanımı etkinleştiriliyor..."
    read -p "HTTP Proxy adresi girin: " HTTP_PROXY
    read -p "HTTPS Proxy adresi girin: " HTTPS_PROXY
    
    fly secrets set API_USE_PROXY=true HTTP_PROXY=$HTTP_PROXY HTTPS_PROXY=$HTTPS_PROXY
    echo "Proxy ayarları yapılandırıldı"
    
    # Uygulamayı yeniden başlat
    echo "Uygulama yeniden başlatılıyor..."
    fly restart
fi

echo "İşlem tamamlandı! Uygulama günlüklerini kontrol edin:"
echo "fly logs"

# Yardımcı bilgiler
echo "Hata durumunda şu komutları kullanabilirsiniz:"
echo "- Günlükleri görüntüle: fly logs"
echo "- Uygulamayı yeniden başlat: fly restart"
echo "- Tüm sırları görüntüle: fly secrets list" 