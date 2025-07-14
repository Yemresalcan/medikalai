#!/usr/bin/env python3
"""
MedikalAI - Configuration Module
Copyright (c) 2024 MedikalAI - All Rights Reserved

PROPRIETARY SOFTWARE - UNAUTHORIZED USE PROHIBITED
This software is protected by copyright law and international treaties.
Any unauthorized copying, distribution, or use is strictly prohibited.

For licensing inquiries: [your-email@domain.com]
"""
import os
from datetime import timedelta
from dotenv import load_dotenv

# .env dosyasını yükle
load_dotenv()

# Veritabanı ayarları
DB_PATH = os.environ.get('DB_PATH', 'kan_tahlil_app.db')

# API konfigürasyonu
GEMINI_API_KEY = os.environ.get('GEMINI_API_KEY')
if not GEMINI_API_KEY:
    print("⚠️  UYARI: GEMINI_API_KEY environment variable bulunamadı!")
    print("Lütfen .env dosyasında GEMINI_API_KEY'inizi tanımlayın.")
    print("Örnek: GEMINI_API_KEY=AIza...")
    GEMINI_API_URL = None
else:
    GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"

# Email ayarları
EMAIL_SETTINGS = {
    'SMTP_SERVER': 'smtp.gmail.com',
    'SMTP_PORT': 587,
    'EMAIL_ADDRESS': 'medikalai.info@gmail.com',
    'EMAIL_PASSWORD': os.environ.get('EMAIL_PASSWORD'),
    'FROM_NAME': 'MedikalAI Sağlık Rehberi'
}

# Flask uygulama ayarları
class Config:
    """Flask uygulama konfigürasyonu"""
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB limit
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=1)
    
    # Güvenlik ayarları
    SECRET_KEY = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'dev-jwt-secret-change-in-production')
    
    # Debug modu
    DEBUG = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    
    # Fly.io API konfigürasyonu
    FLY_API_TOKEN = os.environ.get('FLY_API_TOKEN')
    FLY_APP_NAME = os.environ.get('FLY_APP_NAME') or 'medikalai'

# Abonelik planları
SUBSCRIPTION_PLANS = {
    'free': {
        'name': 'Ücretsiz',
        'price': 0,
        'description': 'Aylık 3 tahlil analizi',
        'analysis_limit': 3,
        'features': ['Temel analiz', 'Sınırlı tahlil sayısı', 'Tahlil geçmişi']
    },
    'basic': {
        'name': 'Temel',
        'price': 49.90,
        'description': 'Aylık 10 tahlil analizi',
        'analysis_limit': 10,
        'features': ['Detaylı analiz', '10 tahlil/ay', 'Tahlil geçmişi', 'PDF rapor indirme']
    },
    'premium': {
        'name': 'Premium',
        'price': 89.90,
        'description': 'Sınırsız tahlil analizi',
        'analysis_limit': float('inf'),
        'features': ['Kapsamlı analiz', 'Sınırsız tahlil', 'Tahlil geçmişi', 'PDF rapor indirme', 'E-posta bildirim', 'Öncelikli destek']
    },
    'family': {
        'name': 'Aile',
        'price': 129.90,
        'description': '5 aile üyesi için sınırsız tahlil analizi',
        'analysis_limit': float('inf'),
        'features': ['Kapsamlı analiz', 'Sınırsız tahlil', '5 aile üyesi', 'Tahlil geçmişi', 'PDF rapor indirme', 'E-posta bildirim', 'Öncelikli destek']
    }
} 