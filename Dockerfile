FROM python:3.9-slim AS builder

WORKDIR /app

# Ön gereksinimler ve bağımlılıkları yükle
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Çalışma zamanı aşaması
FROM python:3.9-slim

# Kullanıcıyı oluştur
RUN addgroup --system app && adduser --system --group app

# Güvenlik için çalışma dizinini hazırla
WORKDIR /app
COPY --from=builder /root/.local /home/app/.local
ENV PATH=/home/app/.local/bin:$PATH

# Uygulama dosyalarını kopyala
COPY . .

# Volume'a erişim için uygulama dizinini yapılandırma
RUN mkdir -p /data && chown -R app:app /data
ENV DB_PATH=/data/kan_tahlil_app.db

# Fly.io için gerekli çevresel değişkenler
ENV PORT=8080
ENV HOST=0.0.0.0

# Kullanıcıyı değiştir
USER app

# Uygulama portunu dışa aç
EXPOSE 8080

# Health check ekle
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/ || exit 1

# Veritabanını oluştur ve uygulamayı başlat
CMD ["sh", "-c", "python -c 'from app import init_db; init_db()' && gunicorn app:app --bind 0.0.0.0:8080 --workers 2 --threads 2 --timeout 60"] 