#!/bin/bash

# Fly.io makinesini güvenli bir şekilde yeniden başlatmak için script

echo "Mevcut makineler kontrol ediliyor..."
fly status

echo "Uygulamaya ait makineleri yeniden başlatıyorum..."
fly apps restart medikalai

echo "Makinelerin başlatıldığını kontrol ediyorum..."
fly status

echo "Loglara bakıyorum, CTRL+C ile çıkabilirsiniz..."
fly logs

echo "İşlem tamamlandı. Uygulamanızı şu adresten kontrol edebilirsiniz:"
echo "https://medikalai.fly.dev" 