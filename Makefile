.PHONY: build up down logs shell clean fly-launch fly-volume fly-deploy fly-open fly-secrets fly-restart quick-start fly-full-deploy

# Docker image ve konteyner ismi
IMAGE_NAME = medikalai
CONTAINER_NAME = medikalai

# Temel komutlar
build:
	docker-compose build

up:
	docker-compose up -d

down:
	docker-compose down

logs:
	docker-compose logs -f

shell:
	docker exec -it $(CONTAINER_NAME) /bin/bash || docker exec -it $(CONTAINER_NAME) /bin/sh

# Temizlik işlemleri
clean:
	docker-compose down -v
	docker rmi $(IMAGE_NAME) || true

# Fly.io deployment komutları
fly-launch:
	fly launch --dockerfile Dockerfile.simple --no-deploy

fly-volume:
	fly volumes create data --size 1 || echo "Volume already exists"

fly-deploy:
	fly deploy --dockerfile Dockerfile.simple

fly-open:
	fly open

fly-restart:
	fly apps restart

# API anahtarlarını Fly.io'da ayarlama
fly-secrets:
	@echo "API anahtarlarınızı girin:"
	@read -p "STRIPE_API_KEY: " STRIPE_API_KEY; \
	read -p "STRIPE_PUBLIC_KEY: " STRIPE_PUBLIC_KEY; \
	read -p "GEMINI_API_KEY: " GEMINI_API_KEY; \
	fly secrets set STRIPE_API_KEY=$$STRIPE_API_KEY STRIPE_PUBLIC_KEY=$$STRIPE_PUBLIC_KEY GEMINI_API_KEY=$$GEMINI_API_KEY

# Hızlı başlatma
quick-start:
	@echo "Uygulamayı başlatıyorum..."
	@if [ ! -f .env ]; then cp .env-example .env && echo ".env dosyası oluşturuldu, lütfen API anahtarlarınızı buraya ekleyin"; fi
	@echo "Docker imajı oluşturuluyor..."
	@make build
	@echo "Konteyner başlatılıyor..."
	@make up
	@echo "Uygulama başlatıldı! http://localhost:8080 adresinden erişebilirsiniz."

# Fly.io için tam deploy
fly-full-deploy:
	@echo "Fly.io tam deployment başlatılıyor..."
	@make fly-launch
	@make fly-volume
	@make fly-secrets
	@make fly-deploy
	@make fly-open
	@echo "Deployment tamamlandı!" 