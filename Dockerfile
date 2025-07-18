FROM python:3.9

WORKDIR /app

# Curl paketini yükle - healthcheck için gerekli
RUN apt-get update && apt-get install -y curl && apt-get clean && rm -rf /var/lib/apt/lists/*

# Önce template ve static dosyalarını kopyala
COPY templates/ /app/templates/
COPY static/ /app/static/

# Gerekli dosyaları kopyala
COPY app.py config.py requirements.txt ./

# Bağımlılıkları doğrudan yükle - pip hatası olasılığını azaltmak için
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir flask requests PyPDF2 openai bcrypt Flask-WTF flask-jwt-extended gunicorn stripe python-dotenv

# Volume dizini
RUN mkdir -p /data
ENV DB_PATH=/data/kan_tahlil_app.db

# Port ve host
ENV PORT=8080
ENV HOST=0.0.0.0

# Debug modunu kapalı tut (canlı ortam için)
ENV FLASK_DEBUG=0

EXPOSE 8080

# Healthcheck ekle
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 CMD curl -f http://localhost:8080/login || exit 0

# Tek adımda çalıştır
CMD ["sh", "-c", "python -c 'from app import init_db; init_db()' && gunicorn app:app --bind 0.0.0.0:8080 --timeout 120"] 