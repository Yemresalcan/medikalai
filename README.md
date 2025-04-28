# Kan Tahlili Yorumlama Web Uygulaması

Bu proje, Flask tabanlı bir web arayüzü ile kullanıcıdan kan tahlili değerlerini alır ve OpenAI API kullanarak tıbbi yorum üretir.

## Kurulum

1. Gerekli Python paketlerini yükleyin:
   ```
   pip install -r requirements.txt
   ```
2. OpenAI API anahtarınızı ortam değişkeni olarak ayarlayın:
   - Windows:
     ```
     set OPENAI_API_KEY=YOUR_OPENAI_API_KEY
     ```
   - Linux/Mac:
     ```
     export OPENAI_API_KEY=YOUR_OPENAI_API_KEY
     ```

3. Uygulamayı başlatın:
   ```
   python app.py
   ```

4. Tarayıcınızda `http://localhost:5000` adresine gidin.

## Özellikler
- Kullanıcıdan temel kan tahlili değerlerini alır.
- OpenAI API ile tıbbi yorum üretir.
- Sonucu ekranda gösterir.

## Notlar
- OpenAI API anahtarınızı güvenli şekilde saklayınız.
- Bu uygulama tıbbi tavsiye yerine geçmez, sadece bilgilendirme amaçlıdır.
