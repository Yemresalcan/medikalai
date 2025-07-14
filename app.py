#!/usr/bin/env python3
"""
MedikalAI - Intelligent Blood Test Analysis Platform
Copyright (c) 2024 MedikalAI - All Rights Reserved

PROPRIETARY SOFTWARE - UNAUTHORIZED USE PROHIBITED
This software is protected by copyright law and international treaties.
Any unauthorized copying, distribution, or use is strictly prohibited.

For licensing inquiries: [your-email@domain.com]
"""

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
import requests
import json
import os
import PyPDF2
from io import BytesIO
import sqlite3
from datetime import datetime, timedelta
import secrets
import bcrypt
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from functools import wraps

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import time
from config import GEMINI_API_URL, GEMINI_API_KEY, Config, EMAIL_SETTINGS, SUBSCRIPTION_PLANS, DB_PATH
from email.mime.base import MIMEBase
from email import encoders
import threading

# .env dosyasını yükle
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    print("python-dotenv kütüphanesi bulunamadı. pip install python-dotenv ile yükleyebilirsiniz.")
    print("Şimdilik environment variable'lar sistem ortamından okunacak.")

# Konfigürasyon zaten yukarıda import edildi

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY



# CSRF koruması
csrf = CSRFProtect(app)

# JWT konfigurasyonu
app.config['JWT_SECRET_KEY'] = Config.JWT_SECRET_KEY
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = Config.JWT_ACCESS_TOKEN_EXPIRES
jwt = JWTManager(app)

# API konfigürasyonu config.py'dan geldi

# Kan tahlili parametreleri ve normal aralıkları
BLOOD_TEST_PARAMETERS = {
    "kanser_gostergeleri": {
        "name": "🧬 Kanser Göstergeleri (Tümör Belirteçleri)",
        "description": "Kanser taraması için kullanılan özel belirteçler",
        "parameters": {
            "CEA": {
                "name": "CEA (Kanser Belirteci)", 
                "min": 0, "max": 5, "unit": "µg/L", 
                "description": "Vücuttaki kanser belirtilerini ölçen test",
                "what_is_it": "Kolon, akciğer ve mide kanserlerinde yükselen özel protein",
                "high_explanation": "Bu değer yüksek çıkmış, bazı kanser türlerinin belirtisi olabilir",
                "high_conditions": [
                    "Kolon kanseri riski",
                    "Akciğer kanseri şüphesi", 
                    "Mide kanseri olasılığı",
                    "Pankreas kanseri riski",
                    "Sigara kullanımına bağlı yükselme"
                ],
                "low_explanation": "Bu değer düşük, kanser açısından iyi bir işaret",
                "low_conditions": ["Normal, endişe yok"]
            },
            "CA 15-3": {
                "name": "CA 15-3 (Meme Kanseri Belirteci)", 
                "min": 0, "max": 31.3, "unit": "U/mL", 
                "description": "Özellikle meme kanseri için kontrol edilen test",
                "what_is_it": "Meme kanserinde yükselen özel bir protein belirteci",
                "high_explanation": "Bu değer normal üstü, meme kanseri riski artmış olabilir",
                "high_conditions": [
                    "Meme kanseri riski",
                    "Meme kanserinin yayılması olasılığı",
                    "Over kanseri şüphesi",
                    "Karaciğer kanseri riski"
                ],
                "low_explanation": "Bu değer düşük, meme kanseri açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            },
            "CA 19-9": {
                "name": "CA 19-9 (Pankreas Kanseri Belirteci)", 
                "min": 0, "max": 37, "unit": "U/mL", 
                "description": "Pankreas ve safra yolu kanserlerini kontrol eder",
                "what_is_it": "Pankreas kanserinde yükselen özel protein belirteci",
                "high_explanation": "Bu değer yüksek, pankreas veya safra kanseri riski var",
                "high_conditions": [
                    "Pankreas kanseri riski",
                    "Safra yolu kanseri şüphesi",
                    "Kolon kanseri olasılığı",
                    "Safra taşı nedeniyle yükselme"
                ],
                "low_explanation": "Bu değer düşük, pankreas kanseri açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            },
            "CA 125": {
                "name": "CA 125 (Over Kanseri Belirteci)", 
                "min": 0, "max": 35, "unit": "U/mL", 
                "description": "Kadınlarda over kanseri taraması için kullanılır",
                "what_is_it": "Over kanserinde yükselen özel protein belirteci",
                "high_explanation": "Bu değer yüksek, over kanseri riski artmış olabilir",
                "high_conditions": [
                    "Over kanseri riski",
                    "Endometriozis olasılığı",
                    "Over kisti şüphesi",
                    "Rahim kanseri riski",
                    "Miyom nedeniyle yükselme"
                ],
                "low_explanation": "Bu değer düşük, over kanseri açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            },
            "PSA": {
                "name": "PSA (Prostat Kanseri Belirteci)", 
                "min": 0, "max": 4, "unit": "ng/mL", 
                "description": "Erkeklerde prostat kanseri taraması",
                "what_is_it": "Prostat bezinden salgılanan, kanser durumunda yükselen protein",
                "high_explanation": "Bu değer yüksek, prostat sorunu veya kanser riski var",
                "high_conditions": [
                    "Prostat kanseri riski",
                    "Prostat büyümesi (BPH)",
                    "Prostat iltihabı",
                    "İdrar yolu enfeksiyonu"
                ],
                "low_explanation": "Bu değer düşük, prostat kanseri açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            },
            "AFP": {
                "name": "AFP (Karaciğer/Testis Kanseri Belirteci)", 
                "min": 0, "max": 20, "unit": "ng/mL", 
                "description": "Karaciğer ve testis kanserlerini kontrol eder",
                "what_is_it": "Karaciğer ve testis kanserlerinde yükselen özel protein",
                "high_explanation": "Bu değer yüksek, karaciğer veya testis kanseri riski var",
                "high_conditions": [
                    "Karaciğer kanseri riski",
                    "Testis kanseri şüphesi",
                    "Karaciğer sirozu olasılığı",
                    "Hepatit B/C komplikasyonu"
                ],
                "low_explanation": "Bu değer düşük, kanser açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            },
            "CA 72-4": {
                "name": "CA 72-4 (Mide Kanseri Belirteci)", 
                "min": 0, "max": 6.9, "unit": "U/mL", 
                "description": "Mide ve kolorektal kanserleri için belirteç",
                "what_is_it": "Mide kanserinde yükselen özel protein belirteci",
                "high_explanation": "Bu değer yüksek, mide kanseri riski var",
                "high_conditions": [
                    "Mide kanseri riski",
                    "Kolorektal kanser şüphesi",
                    "Pankreas kanseri olasılığı"
                ],
                "low_explanation": "Bu değer düşük, mide kanseri açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            },
            "CA 27-29": {
                "name": "CA 27-29 (Meme Kanseri İzlem Belirteci)", 
                "min": 0, "max": 38, "unit": "U/mL", 
                "description": "Meme kanseri takibi için kullanılan belirteç",
                "what_is_it": "Meme kanserinin seyrini takip etmek için kullanılan protein",
                "high_explanation": "Bu değer yüksek, meme kanseri takibi gerekli",
                "high_conditions": [
                    "Meme kanseri nüksü riski",
                    "Metastaz olasılığı",
                    "Tedavi yanıtı değerlendirmesi gerekli"
                ],
                "low_explanation": "Bu değer düşük, meme kanseri takibi açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            },
            "CYFRA 21-1": {
                "name": "CYFRA 21-1 (Akciğer Kanseri Belirteci)", 
                "min": 0, "max": 3.3, "unit": "ng/mL", 
                "description": "Akciğer kanseri için özel belirteç",
                "what_is_it": "Akciğer kanserinde yükselen sitokeratin fragmanı",
                "high_explanation": "Bu değer yüksek, akciğer kanseri riski var",
                "high_conditions": [
                    "Akciğer kanseri riski",
                    "KOAH ile ilişkili kanser riski",
                    "Sigara kaynaklı kanser şüphesi"
                ],
                "low_explanation": "Bu değer düşük, akciğer kanseri açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            },
            "NSE": {
                "name": "NSE (Nöroendokrin Tümör Belirteci)", 
                "min": 0, "max": 16.3, "unit": "ng/mL", 
                "description": "Nöroendokrin tümörler için belirteç",
                "what_is_it": "Sinir sistemi kaynaklı tümörlerde yükselen enzim",
                "high_explanation": "Bu değer yüksek, nöroendokrin tümör riski var",
                "high_conditions": [
                    "Küçük hücreli akciğer kanseri riski",
                    "Nöroendokrin tümör şüphesi",
                    "Pankreas adacık hücresi tümörü olasılığı"
                ],
                "low_explanation": "Bu değer düşük, nöroendokrin tümör açısından iyi",
                "low_conditions": ["Normal, endişe yok"]
            }
        }
    },
    "hemogram": {
        "name": "🩸 Tam Kan Sayımı (Hemogram)",
        "description": "Kan hücrelerinin sayısı ve özellikleri",
        "parameters": {
            "WBC": {
                "name": "WBC (Akyuvar - Savunma Hücreleri)", 
                "min": 4, "max": 10.5, "unit": "x10³/µL", 
                "description": "Vücudun enfeksiyonlara karşı savunma hücreleri",
                "what_is_it": "Hastalıklara karşı savaşan beyaz kan hücreleri",
                "high_explanation": "Akyuvar sayınız yüksek, vücudunuzda enfeksiyon/iltihap olabilir",
                "high_conditions": [
                    "Bakteriyel enfeksiyon riski",
                    "Viral enfeksiyon olasılığı",
                    "Kan kanseri (lösemi) şüphesi",
                    "Stres/sigara nedeniyle yükselme",
                    "İlaç yan etkisi"
                ],
                "low_explanation": "Akyuvar sayınız düşük, bağışıklığınız zayıflamış olabilir",
                "low_conditions": [
                    "Bağışıklık sistemi zayıflığı",
                    "Viral enfeksiyon sonrası düşme",
                    "İlaç yan etkisi (kemoterapi vb.)",
                    "Kemik iliği problemi",
                    "Otoimmün hastalık riski"
                ]
            },
            "HGB": {
                "name": "HGB (Hemoglobin - Oksijen Taşıyıcısı)", 
                "min": 12.5, "max": 16, "unit": "g/dL", 
                "description": "Kanda oksijen taşıyan kırmızı protein",
                "what_is_it": "Kandaki oksijen taşıyan ana madde, kansızlık göstergesi",
                "high_explanation": "Hemoglobin değeriniz yüksek, kan kalınlaşmış olabilir",
                "high_conditions": [
                    "Kan kalınlaşması (polisitemi)",
                    "Kalp hastalığı riski",
                    "Akciğer hastalığı olasılığı",
                    "Yüksek rakım etkisi",
                    "Dehidrasyon (susuzluk)"
                ],
                "low_explanation": "Hemoglobin değeriniz düşük, kansızlık (anemi) var",
                "low_conditions": [
                    "Demir eksikliği anemisi",
                    "Vitamin B12 eksikliği",
                    "Kronik hastalık anemisi",
                    "Kan kaybı (adet, mide kanaması)",
                    "Beslenme bozukluğu"
                ]
            },
            "HCT": {
                "name": "HCT (Hematokrit - Kan Yoğunluğu)", 
                "min": 37, "max": 47, "unit": "%", 
                "description": "Kandaki kırmızı kan hücresi yüzdesi",
                "what_is_it": "Kanınızın ne kadarının kırmızı hücrelerden oluştuğunu gösterir",
                "high_explanation": "Kan yoğunluğunuz artmış, kan kalınlaşmış olabilir",
                "high_conditions": [
                    "Kan kalınlaşması riski",
                    "Kalp krizi riski artışı",
                    "İnme riski",
                    "Dehidrasyon (susuzluk)",
                    "Akciğer hastalığı"
                ],
                "low_explanation": "Kan yoğunluğunuz azalmış, kansızlık belirtisi",
                "low_conditions": [
                    "Anemi (kansızlık)",
                    "Demir eksikliği",
                    "Vitamin eksiklikleri",
                    "Kronik hastalık",
                    "Kan kaybı"
                ]
            },
            "RBC": {
                "name": "RBC (Alyuvar - Kırmızı Kan Hücreleri)", 
                "min": 4.2, "max": 5.4, "unit": "x10⁶/µL", 
                "description": "Oksijen taşıyan kırmızı kan hücrelerinin sayısı",
                "what_is_it": "Vücudunuza oksijen taşıyan kırmızı kan hücreleri",
                "high_explanation": "Kırmızı kan hücresi sayınız fazla, kan kalınlaşabilir",
                "high_conditions": [
                    "Polisitemi (kan kalınlaşması)",
                    "Kalp hastalığı riski",
                    "Tromboz riski",
                    "Akciğer hastalığı",
                    "Böbrek hastalığı"
                ],
                "low_explanation": "Kırmızı kan hücresi sayınız az, anemi var",
                "low_conditions": [
                    "Anemi (kansızlık)",
                    "Demir eksikliği",
                    "B12/Folik asit eksikliği",
                    "Kemik iliği problemi",
                    "Kronik böbrek hastalığı"
                ]
            },
            "PLT": {
                "name": "PLT (Trombosit - Pıhtılaşma Hücreleri)", 
                "min": 150, "max": 450, "unit": "x10³/µL", 
                "description": "Kan pıhtılaşmasını sağlayan hücreler",
                "what_is_it": "Kanamayı durduran, yara iyileştiren kan hücreleri",
                "high_explanation": "Trombosit sayınız yüksek, kan pıhtısı riski artabilir",
                "high_conditions": [
                    "Tromboz (damar tıkanıklığı) riski",
                    "Kalp krizi riski",
                    "İnme riski",
                    "Kan kanseri olasılığı",
                    "İltihaplı hastalık"
                ],
                "low_explanation": "Trombosit sayınız düşük, kanama riski var",
                "low_conditions": [
                    "Kolay kanama eğilimi",
                    "Morarma (ekimoz) artışı",
                    "İlaç yan etkisi",
                    "Viral enfeksiyon sonrası",
                    "Kemik iliği problemi"
                ]
            },
            "MCV": {"name": "MCV (Ortalama Eritrosit Hacmi)", "min": 80, "max": 100, "unit": "fL", "description": "Kırmızı kan hücrelerinin ortalama boyutu"},
            "MCH": {"name": "MCH (Ortalama Eritrosit Hemoglobini)", "min": 27, "max": 32, "unit": "pg", "description": "Her kırmızı kan hücresindeki hemoglobin miktarı"},
            "MCHC": {"name": "MCHC (Ortalama Eritrosit Hemoglobin Konsantrasyonu)", "min": 32, "max": 36, "unit": "g/dL", "description": "Kırmızı kan hücrelerindeki hemoglobin konsantrasyonu"},
            "RDW": {"name": "RDW (Eritrosit Dağılım Genişliği)", "min": 11.5, "max": 14.5, "unit": "%", "description": "Kırmızı kan hücrelerinin boyut farklılığı"},
            "NEU": {"name": "NEU (Nötrofil)", "min": 50, "max": 70, "unit": "%", "description": "Bakteriyel enfeksiyonlara karşı savaşan hücreler"},
            "LYM": {"name": "LYM (Lenfosit)", "min": 20, "max": 40, "unit": "%", "description": "Viral enfeksiyonlara karşı savaşan hücreler"},
            "MON": {"name": "MON (Monosit)", "min": 2, "max": 8, "unit": "%", "description": "Büyük yabancı maddeleri yok eden hücreler"},
            "EOS": {"name": "EOS (Eozinofil)", "min": 1, "max": 4, "unit": "%", "description": "Alerjik reaksiyonlarda rol oynayan hücreler"},
            "BAS": {"name": "BAS (Bazofil)", "min": 0, "max": 0.7, "unit": "%", "description": "Alerjik reaksiyonlarda rol oynayan nadir hücreler"},
            "PDW": {"name": "PDW (Trombosit Dağılım Genişliği)", "min": 9.9, "max": 15.4, "unit": "%", "description": "Trombositlerin boyut farklılığı"}
        }
    },
    "elektrolitler": {
        "name": "⚖️ Elektrolitler ve Mineraller",
        "description": "Vücut sıvılarındaki elektrolit dengesi",
        "parameters": {
            "Na": {"name": "Sodyum", "min": 136, "max": 146, "unit": "mmol/L", "description": "Sıvı dengesi ve sinir iletimi için kritik"},
            "K": {"name": "Potasyum", "min": 3.5, "max": 5.1, "unit": "mmol/L", "description": "Kalp ritmi ve kas fonksiyonu için önemli"},
            "Cl": {"name": "Klorür", "min": 101, "max": 109, "unit": "mmol/L", "description": "Asit-baz dengesi için gerekli"},
            "Ca": {"name": "Kalsiyum", "min": 8.8, "max": 10.6, "unit": "mg/dL", "description": "Kemik sağlığı ve kas kasılması için gerekli"},
            "P": {"name": "Fosfor", "min": 2.5, "max": 4.5, "unit": "mg/dL", "description": "Kemik sağlığı ve enerji metabolizması"},
            "Mg": {"name": "Magnezyum", "min": 1.9, "max": 2.5, "unit": "mg/dL", "description": "Kas fonksiyonu ve sinir iletimi için önemli"},
            "Fe": {"name": "Demir", "min": 65, "max": 175, "unit": "µg/dL", "description": "Hemoglobin üretimi için gerekli"},
            "Zn": {"name": "Çinko", "min": 70, "max": 120, "unit": "µg/dL", "description": "Bağışıklık sistemi ve yara iyileşmesi"}
        }
    },
    "bobrek_fonksiyonlari": {
        "name": "🫘 Böbrek Fonksiyonları",
        "description": "Böbreklerin çalışma durumu",
        "parameters": {
            "BUN": {"name": "Üre", "min": 8, "max": 20, "unit": "mg/dL", "description": "Böbrek fonksiyonunun temel göstergesi"},
            "Creatinine": {"name": "Kreatinin", "min": 0.66, "max": 1.09, "unit": "mg/dL", "description": "Böbrek filtrasyon hızının göstergesi"},
            "eGFR": {"name": "eGFR (Filtrasyon Hızı)", "min": 90, "max": 999, "unit": "mL/min/1.73m²", "description": "Böbrek fonksiyonunun en doğru ölçümü"},
            "Uric_Acid": {"name": "Ürik Asit", "min": 2.6, "max": 6, "unit": "mg/dL", "description": "Gut hastalığı ve böbrek taşı riski göstergesi"}
        }
    },
    "karaciger_fonksiyonlari": {
        "name": "🍃 Karaciğer Fonksiyonları",
        "description": "Karaciğerin çalışma durumu",
        "parameters": {
            "ALT": {"name": "ALT (Alanin Aminotransferaz)", "min": 0, "max": 35, "unit": "U/L", "description": "Karaciğer hasarının önemli göstergesi"},
            "AST": {"name": "AST (Aspartat Aminotransferaz)", "min": 10, "max": 50, "unit": "U/L", "description": "Karaciğer ve kalp kasında bulunan enzim"},
            "GGT": {"name": "GGT (Gama Glutamil Transferaz)", "min": 0, "max": 38, "unit": "U/L", "description": "Karaciğer ve safra yolu hastalıkları göstergesi"},
            "ALP": {"name": "Alkalen Fosfataz", "min": 0, "max": 130, "unit": "U/L", "description": "Karaciğer, kemik ve safra yolu göstergesi"},
            "Albumin": {"name": "Albümin", "min": 35, "max": 52, "unit": "g/L", "description": "Karaciğerin protein üretim kapasitesi"},
            "Total_Bilirubin": {"name": "Total Bilirubin", "min": 0.3, "max": 1.2, "unit": "mg/dL", "description": "Karaciğer ve sarılık göstergesi"},
            "Direct_Bilirubin": {"name": "Direkt Bilirubin", "min": 0, "max": 0.2, "unit": "mg/dL", "description": "Karaciğer ve safra yolu tıkanıklığı göstergesi"},
            "Indirect_Bilirubin": {"name": "İndirekt Bilirubin", "min": 0.1, "max": 1, "unit": "mg/dL", "description": "Kan hücresi yıkımı göstergesi"}
        }
    },
    "pankreas_enzimler": {
        "name": "🍬 Pankreas ve Diğer Enzimler",
        "description": "Pankreas fonksiyonu ve sindirim enzimleri",
        "parameters": {
            "Amylase": {"name": "Amilaz", "min": 22, "max": 80, "unit": "U/L", "description": "Pankreas iltihabı ve hastalıkları göstergesi"},
            "Lipase": {"name": "Lipaz", "min": 0, "max": 67, "unit": "U/L", "description": "Pankreas hastalıkları için hassas gösterge"},
            "LDH": {"name": "LDH (Laktat Dehidrogenaz)", "min": 0, "max": 248, "unit": "U/L", "description": "Hücre hasarı ve organ fonksiyonu göstergesi"},
            "CK": {"name": "CK (Kreatin Kinaz)", "min": 30, "max": 200, "unit": "U/L", "description": "Kas hasarı ve kalp krizi göstergesi"}
        }
    },
    "seker_metabolizma": {
        "name": "🍭 Şeker ve Metabolizma",
        "description": "Kan şekeri ve metabolik göstergeler",
        "parameters": {
            "Glucose": {
                "name": "Glukoz (Kan Şekeri)", 
                "min": 74, "max": 106, "unit": "mg/dL", 
                "description": "Açlık kan şekeri seviyesi",
                "what_is_it": "Vücudunuzun enerji kaynağı olan kan şekeri",
                "high_explanation": "Kan şekeriniz yüksek, diyabet riski var",
                "high_conditions": [
                    "Tip 2 Diyabet riski",
                    "Prediyabet (diyabet öncesi)",
                    "İnsülin direnci",
                    "Metabolik sendrom",
                    "Stres/hastalık nedeniyle yükselme"
                ],
                "low_explanation": "Kan şekeriniz düşük, hipoglisemi var",
                "low_conditions": [
                    "Açlık hipoglisemisi",
                    "İnsülin fazlalığı",
                    "Karaciğer hastalığı",
                    "Aşırı egzersiz sonrası",
                    "İlaç yan etkisi"
                ]
            },
            "HbA1c": {
                "name": "HbA1c (Şeker Hafızası)", 
                "min": 4, "max": 5.6, "unit": "%", 
                "description": "Son 2-3 ayın ortalama kan şekeri",
                "what_is_it": "Son 3 ayın kan şekeri ortalamasını gösteren özel test",
                "high_explanation": "Şeker hafızanız yüksek, diyabet kontrolü gerekli",
                "high_conditions": [
                    "Diyabet tanısı (>6.5%)",
                    "Prediyabet (5.7-6.4%)",
                    "Şeker kontrolsüzlüğü",
                    "Komplikasyon riski",
                    "İlaç ayarı gerekiyor"
                ],
                "low_explanation": "Şeker hafızanız çok düşük, kontrol gerekli",
                "low_conditions": [
                    "Çok sıkı şeker kontrolü",
                    "Hipoglisemi riski",
                    "Beslenme bozukluğu",
                    "İlaç dozu fazla olabilir"
                ]
            },
            "Insulin": {
                "name": "İnsülin (Şeker Hormonu)", 
                "min": 2.6, "max": 24.9, "unit": "µIU/mL", 
                "description": "Pankreastan salgılanan şeker düzenleyici hormon",
                "what_is_it": "Kan şekerinizi düşüren vücut hormonu",
                "high_explanation": "İnsülin seviyeniz yüksek, direnç gelişmiş olabilir",
                "high_conditions": [
                    "İnsülin direnci",
                    "Metabolik sendrom",
                    "Tip 2 diyabet gelişme riski",
                    "Obezite",
                    "Polikistik over sendromu"
                ],
                "low_explanation": "İnsülin seviyeniz düşük, pankreas yorgun olabilir",
                "low_conditions": [
                    "Pankreas yetmezliği",
                    "Tip 1 diyabet riski",
                    "Beslenme bozukluğu",
                    "Kronik hastalık"
                ]
            }
        }
    },
    "lipid_profili": {
        "name": "🫀 Lipid Profili (Kolesterol)",
        "description": "Kalp-damar sağlığı göstergeleri",
        "parameters": {
            "Total_Cholesterol": {
                "name": "Total Kolesterol (Genel)", 
                "min": 0, "max": 200, "unit": "mg/dL", 
                "description": "Kandaki toplam kolesterol miktarı",
                "what_is_it": "Vücudunuzdaki toplam yağ maddesi (iyi + kötü kolesterol)",
                "high_explanation": "Kolesterolünüz yüksek, kalp krizi riski artıyor",
                "high_conditions": [
                    "Kalp krizi riski",
                    "Damar tıkanıklığı riski",
                    "İnme riski",
                    "Ateroskleroz (damar sertliği)",
                    "Beslenme bozukluğu"
                ],
                "low_explanation": "Kolesterolünüz çok düşük, hormon problemleri olabilir",
                "low_conditions": [
                    "Hormon eksikliği",
                    "Beslenme yetersizliği",
                    "Karaciğer problemi",
                    "Hipertiroidi riski"
                ]
            },
            "LDL": {
                "name": "LDL (Kötü Kolesterol)", 
                "min": 0, "max": 100, "unit": "mg/dL", 
                "description": "Damarları tıkayan zararlı kolesterol",
                "what_is_it": "Damarlarınızı tıkayan, kalp krizine yol açan kötü kolesterol",
                "high_explanation": "Kötü kolesterolünüz yüksek, acil diyet gerekli",
                "high_conditions": [
                    "Kalp krizi riski (yüksek)",
                    "Koroner arter hastalığı",
                    "Damar tıkanıklığı",
                    "İnme riski",
                    "Ailevi yüksek kolesterol"
                ],
                "low_explanation": "Kötü kolesterolünüz düşük, harika!",
                "low_conditions": ["Mükemmel kalp sağlığı", "İyi beslenme alışkanlığı"]
            },
            "HDL": {
                "name": "HDL (İyi Kolesterol)", 
                "min": 40, "max": 999, "unit": "mg/dL", 
                "description": "Damarları temizleyen koruyucu kolesterol",
                "what_is_it": "Damarlarınızı temizleyen, kalbi koruyan iyi kolesterol",
                "high_explanation": "İyi kolesterolünüz yüksek, kalp sağlığınız çok iyi!",
                "high_conditions": ["Mükemmel kalp koruması", "Uzun yaşam beklentisi"],
                "low_explanation": "İyi kolesterolünüz düşük, kalp riski artıyor",
                "low_conditions": [
                    "Kalp krizi riski artışı",
                    "Egzersiz eksikliği",
                    "Sigara kullanımı etkisi",
                    "Obezite",
                    "Diyabet riski"
                ]
            },
            "Triglycerides": {
                "name": "Trigliserit (Kan Yağı)", 
                "min": 0, "max": 150, "unit": "mg/dL", 
                "description": "Kandaki yağ parçacıkları",
                "what_is_it": "Vücudunuzda depolanan fazla yağlar",
                "high_explanation": "Kan yağınız yüksek, kalp ve pankreas riski var",
                "high_conditions": [
                    "Kalp hastalığı riski",
                    "Pankreatit (pankreas iltihabı)",
                    "Diyabet riski",
                    "Metabolik sendrom",
                    "Aşırı alkol/şeker tüketimi"
                ],
                "low_explanation": "Kan yağınız düşük, çok iyi!",
                "low_conditions": ["Sağlıklı beslenme", "İyi metabolizma"]
            }
        }
    },
    "hormonlar": {
        "name": "🧪 Hormonlar",
        "description": "Endokrin sistem hormonları",
        "parameters": {
            "TSH": {"name": "TSH (Tiroid Uyarıcı Hormon)", "min": 0.27, "max": 4.2, "unit": "µIU/mL", "description": "Tiroid fonksiyonunun ana göstergesi"},
            "Free_T4": {"name": "Serbest T4", "min": 0.93, "max": 1.7, "unit": "ng/dL", "description": "Aktif serbest T4 hormonu"},
            "Free_T3": {"name": "Serbest T3", "min": 2.0, "max": 4.4, "unit": "pg/mL", "description": "Aktif serbest T3 hormonu"},
            "Vitamin_D": {"name": "Vitamin D", "min": 30, "max": 100, "unit": "ng/mL", "description": "Kemik sağlığı ve bağışıklık sistemi"},
            "Vitamin_B12": {"name": "Vitamin B12", "min": 300, "max": 900, "unit": "pg/mL", "description": "Sinir sistemi ve kan üretimi"},
            "Folate": {"name": "Folik Asit", "min": 2.7, "max": 17, "unit": "ng/mL", "description": "DNA sentezi ve hücre bölünmesi"},
            "Ferritin": {"name": "Ferritin", "min": 15, "max": 150, "unit": "ng/mL", "description": "Vücut demir depoları göstergesi"}
        }
    },
    "inflamasyon": {
        "name": "🔥 İnflamasyon Göstergeleri",
        "description": "Vücuttaki iltihap ve enfeksiyon göstergeleri",
        "parameters": {
            "CRP": {"name": "CRP (C-Reaktif Protein)", "min": 0, "max": 3, "unit": "mg/L", "description": "Genel iltihap göstergesi"},
            "ESR": {"name": "ESR (Sedimentasyon Hızı)", "min": 0, "max": 20, "unit": "mm/saat", "description": "İltihap ve kronik hastalık göstergesi"},
            "Procalcitonin": {"name": "Prokalsitonin", "min": 0, "max": 0.05, "unit": "ng/mL", "description": "Bakteriyel enfeksiyon göstergesi"}
        }
    }
}

# Hastalık risk algoritmaları
DISEASE_RISK_ALGORITHMS = {
    "anemi": {
        "name": "Anemi (Kansızlık)",
        "description": "Kandaki hemoglobin veya kırmızı kan hücresi eksikliği",
        "parameters": ["HGB", "HCT", "RBC", "Ferritin", "Vitamin_B12", "Folate"],
        "conditions": [
            {"param": "HGB", "operator": "<", "value": 12, "weight": 40},
            {"param": "HCT", "operator": "<", "value": 36, "weight": 30},
            {"param": "RBC", "operator": "<", "value": 4.0, "weight": 20},
            {"param": "Ferritin", "operator": "<", "value": 15, "weight": 30},
            {"param": "Vitamin_B12", "operator": "<", "value": 300, "weight": 25},
            {"param": "Folate", "operator": "<", "value": 2.7, "weight": 25}
        ]
    },
    "diyabet": {
        "name": "Tip 2 Diyabet",
        "description": "Kan şekeri yüksekliği ve insulin direnci",
        "parameters": ["Glucose", "HbA1c", "Insulin"],
        "conditions": [
            {"param": "Glucose", "operator": ">", "value": 126, "weight": 50},
            {"param": "HbA1c", "operator": ">", "value": 6.5, "weight": 60},
            {"param": "Insulin", "operator": ">", "value": 25, "weight": 30}
        ]
    },
    "hipotiroidi": {
        "name": "Hipotiroidi (Tiroid Yetersizliği)",
        "description": "Tiroid bezinin yetersiz hormon üretimi",
        "parameters": ["TSH", "Free_T4", "Free_T3"],
        "conditions": [
            {"param": "TSH", "operator": ">", "value": 4.5, "weight": 60},
            {"param": "Free_T4", "operator": "<", "value": 0.8, "weight": 40},
            {"param": "Free_T3", "operator": "<", "value": 1.8, "weight": 30}
        ]
    },
    "karaciger_hastaligi": {
        "name": "Karaciğer Fonksiyon Bozukluğu",
        "description": "Karaciğer enzimlerinin yüksek olması",
        "parameters": ["ALT", "AST", "GGT", "Total_Bilirubin", "Albumin"],
        "conditions": [
            {"param": "ALT", "operator": ">", "value": 40, "weight": 35},
            {"param": "AST", "operator": ">", "value": 40, "weight": 35},
            {"param": "GGT", "operator": ">", "value": 50, "weight": 30},
            {"param": "Total_Bilirubin", "operator": ">", "value": 1.5, "weight": 40},
            {"param": "Albumin", "operator": "<", "value": 30, "weight": 30}
        ]
    },
    "bobrek_hastaligi": {
        "name": "Böbrek Fonksiyon Bozukluğu", 
        "description": "Böbrek filtrasyon kapasitesinin azalması",
        "parameters": ["Creatinine", "BUN", "eGFR", "Uric_Acid"],
        "conditions": [
            {"param": "Creatinine", "operator": ">", "value": 1.2, "weight": 50},
            {"param": "BUN", "operator": ">", "value": 25, "weight": 30},
            {"param": "eGFR", "operator": "<", "value": 60, "weight": 60},
            {"param": "Uric_Acid", "operator": ">", "value": 7, "weight": 20}
        ]
    },
    "kalp_hastaliği_riski": {
        "name": "Kardiyovasküler Hastalık Riski",
        "description": "Kalp ve damar hastalığı gelişme riski",
        "parameters": ["Total_Cholesterol", "LDL", "HDL", "Triglycerides", "CRP"],
        "conditions": [
            {"param": "Total_Cholesterol", "operator": ">", "value": 240, "weight": 30},
            {"param": "LDL", "operator": ">", "value": 130, "weight": 40},
            {"param": "HDL", "operator": "<", "value": 35, "weight": 35},
            {"param": "Triglycerides", "operator": ">", "value": 200, "weight": 30},
            {"param": "CRP", "operator": ">", "value": 3, "weight": 25}
        ]
    },
    "infeksiyon": {
        "name": "Enfeksiyon/İltihap",
        "description": "Vücutta aktif enfeksiyon veya iltihap varlığı",
        "parameters": ["WBC", "NEU", "CRP", "ESR", "Procalcitonin"],
        "conditions": [
            {"param": "WBC", "operator": ">", "value": 11, "weight": 30},
            {"param": "NEU", "operator": ">", "value": 75, "weight": 25},
            {"param": "CRP", "operator": ">", "value": 10, "weight": 40},
            {"param": "ESR", "operator": ">", "value": 30, "weight": 25},
            {"param": "Procalcitonin", "operator": ">", "value": 0.25, "weight": 50}
        ]
        },
    "demir_eksikligi": {
        "name": "Demir Eksikliği",
        "description": "Vücutta demir depolarının azalması",
        "parameters": ["Fe", "Ferritin", "HGB", "MCV"],
        "conditions": [
            {"param": "Fe", "operator": "<", "value": 60, "weight": 30},
            {"param": "Ferritin", "operator": "<", "value": 12, "weight": 50},
            {"param": "HGB", "operator": "<", "value": 12, "weight": 30},
            {"param": "MCV", "operator": "<", "value": 80, "weight": 35}
        ]
    },
    "pankreatit": {
        "name": "Pankreatit (Pankreas İltihabı)",
        "description": "Pankreas enzimlerinin yüksekliği pankreas iltihabını gösterebilir",
        "parameters": ["Amylase", "Lipase"],
        "conditions": [
            {"param": "Amylase", "operator": ">", "value": 100, "weight": 60},
            {"param": "Lipase", "operator": ">", "value": 80, "weight": 70}
        ]
    },
    "prediabetes": {
        "name": "Prediyabet (Diyabet Öncesi)",
        "description": "Normal ve diyabet arasında kan şekeri seviyesi",
        "parameters": ["Glucose", "HbA1c"],
        "conditions": [
            {"param": "Glucose", "operator": ">", "value": 100, "weight": 50},
            {"param": "HbA1c", "operator": ">", "value": 5.7, "weight": 60}
        ]
    },
    "hipertiroidi": {
        "name": "Hipertiroidi (Tiroid Aşırı Çalışması)",
        "description": "Tiroid bezinin aşırı hormon üretimi",
        "parameters": ["TSH", "Free_T4", "Free_T3"],
        "conditions": [
            {"param": "TSH", "operator": "<", "value": 0.1, "weight": 60},
            {"param": "Free_T4", "operator": ">", "value": 1.8, "weight": 40},
            {"param": "Free_T3", "operator": ">", "value": 4.5, "weight": 30}
        ]
    },
    "vitamin_d_eksikligi": {
        "name": "Vitamin D Eksikliği",
        "description": "Kemik sağlığı ve bağışıklık sistemi için kritik vitamin eksikliği",
        "parameters": ["Vitamin_D", "Ca", "P"],
        "conditions": [
            {"param": "Vitamin_D", "operator": "<", "value": 20, "weight": 70},
            {"param": "Ca", "operator": "<", "value": 8.5, "weight": 20},
            {"param": "P", "operator": "<", "value": 2.5, "weight": 10}
        ]
    },
    "b12_eksikligi": {
        "name": "Vitamin B12 Eksikliği",
        "description": "Sinir sistemi ve kan üretimi için gerekli vitamin eksikliği",
        "parameters": ["Vitamin_B12", "HGB", "MCV"],
        "conditions": [
            {"param": "Vitamin_B12", "operator": "<", "value": 200, "weight": 70},
            {"param": "HGB", "operator": "<", "value": 12, "weight": 20},
            {"param": "MCV", "operator": ">", "value": 100, "weight": 30}
        ]
    }
}


def parse_blood_test_from_text(text):
    """PDF metninden kan tahlili parametrelerini çıkarır"""
    import re
    
    extracted_params = {}
    lines = text.split('\n')
    
    # Yaygın parametre eşleştirmeleri
    parameter_patterns = {
        'WBC': r'(?:WBC|white blood cell|akyuvar|beyaz kan).*?([0-9]+\.?[0-9]*)',
        'HGB': r'(?:HGB|hemoglobin|hgb).*?([0-9]+\.?[0-9]*)',
        'HCT': r'(?:HCT|hematokrit|hct).*?([0-9]+\.?[0-9]*)',
        'RBC': r'(?:RBC|red blood cell|alyuvar|kırmızı kan).*?([0-9]+\.?[0-9]*)',
        'PLT': r'(?:PLT|platelet|trombosit).*?([0-9]+\.?[0-9]*)',
        'MCV': r'(?:MCV|mcv).*?([0-9]+\.?[0-9]*)',
        'MCH': r'(?:MCH|mch).*?([0-9]+\.?[0-9]*)',
        'MCHC': r'(?:MCHC|mchc).*?([0-9]+\.?[0-9]*)',
        'NEU': r'(?:NEU|nötrofil|neutrophil).*?([0-9]+\.?[0-9]*)',
        'LYM': r'(?:LYM|lenfosit|lymphocyte).*?([0-9]+\.?[0-9]*)',
        'MON': r'(?:MON|monosit|monocyte).*?([0-9]+\.?[0-9]*)',
        'EOS': r'(?:EOS|eozinofil|eosinophil).*?([0-9]+\.?[0-9]*)',
        'BAS': r'(?:BAS|bazofil|basophil).*?([0-9]+\.?[0-9]*)',
        'Glucose': r'(?:glucose|glukoz|şeker).*?([0-9]+\.?[0-9]*)',
        'BUN': r'(?:BUN|üre|urea).*?([0-9]+\.?[0-9]*)',
        'Creatinine': r'(?:creatinine|kreatinin).*?([0-9]+\.?[0-9]*)',
        'ALT': r'(?:ALT|SGPT|alanin).*?([0-9]+\.?[0-9]*)',
        'AST': r'(?:AST|SGOT|aspartat).*?([0-9]+\.?[0-9]*)',
        'GGT': r'(?:GGT|ggt|gama glutamil).*?([0-9]+\.?[0-9]*)',
        'ALP': r'(?:ALP|alkalen fosfataz|alkaline phosphatase).*?([0-9]+\.?[0-9]*)',
        'Albumin': r'(?:albumin|albümin).*?([0-9]+\.?[0-9]*)',
        'Amylase': r'(?:amilaz|amylase).*?([0-9]+\.?[0-9]*)',
        'Lipase': r'(?:lipaz|lipase).*?([0-9]+\.?[0-9]*)',
        'LDH': r'(?:LDH|ldh|laktat dehidrogenaz).*?([0-9]+\.?[0-9]*)',
        'HbA1c': r'(?:HbA1c|hba1c|hemoglobin a1c|glikozillenmiş).*?([0-9]+\.?[0-9]*)',
        'Insulin': r'(?:insulin|insülin).*?([0-9]+\.?[0-9]*)',
        'Total_Bilirubin': r'(?:total bilirubin|toplam bilirubin).*?([0-9]+\.?[0-9]*)',
        'Direct_Bilirubin': r'(?:direct bilirubin|direkt bilirubin).*?([0-9]+\.?[0-9]*)',
        'Indirect_Bilirubin': r'(?:indirect bilirubin|indirekt bilirubin).*?([0-9]+\.?[0-9]*)',
        'Total_Cholesterol': r'(?:total cholesterol|toplam kolesterol).*?([0-9]+\.?[0-9]*)',
        'LDL': r'(?:LDL|ldl).*?([0-9]+\.?[0-9]*)',
        'HDL': r'(?:HDL|hdl).*?([0-9]+\.?[0-9]*)',
        'Triglycerides': r'(?:triglyceride|trigliserit).*?([0-9]+\.?[0-9]*)',
        'TSH': r'(?:TSH|tsh).*?([0-9]+\.?[0-9]*)',
        'Free_T4': r'(?:free t4|serbest t4|ft4).*?([0-9]+\.?[0-9]*)',
        'Vitamin_D': r'(?:vitamin d|d vitamini).*?([0-9]+\.?[0-9]*)',
        'Vitamin_B12': r'(?:vitamin b12|b12 vitamini).*?([0-9]+\.?[0-9]*)',
        'Ferritin': r'(?:ferritin|ferritin).*?([0-9]+\.?[0-9]*)',
        'CRP': r'(?:CRP|c.?reaktif protein).*?([0-9]+\.?[0-9]*)',
        # Kanser belirteçleri için gelişmiş regex'ler - çok daha kapsamlı
        'CEA': r'(?:CEA|cea|C\.?E\.?A\.?|karsinoembriyonik|carcinoembryonic|Karsinoembriyonik|antijen.*?CEA|CEA.*?antijen).*?([0-9]+\.?[0-9]*)',
        'CA 15-3': r'(?:CA\s?15\-3|ca\s?15\-3|CA\s?15\.3|ca\s?15\.3|CA15\-3|ca15\-3|CA153|ca153|meme.*?belir).*?([0-9]+\.?[0-9]*)',
        'CA 19-9': r'(?:CA\s?19\-9|ca\s?19\-9|CA\s?19\.9|ca\s?19\.9|CA19\-9|ca19\-9|CA199|ca199|pankreas.*?belir).*?([0-9]+\.?[0-9]*)',
        'CA 125': r'(?:CA\s?125|ca\s?125|CA\s?12\.5|ca\s?12\.5|CA125|ca125|over.*?belir|ovarian).*?([0-9]+\.?[0-9]*)',
        'PSA': r'(?:PSA|psa|P\.?S\.?A\.?|prostat.*?spesifik|prostate.*?specific|Prostat.*?Spesifik).*?([0-9]+\.?[0-9]*)',
        'AFP': r'(?:AFP|afp|A\.?F\.?P\.?|alfa.*?fetoprotein|alpha.*?fetoprotein|Alfa.*?Fetoprotein).*?([0-9]+\.?[0-9]*)',
        # Ek kanser belirteçleri
        'CA 72-4': r'(?:CA\s?72\-4|ca\s?72\-4|CA724|ca724)[\s\:]*([0-9]+\.?[0-9]*)',
        'CA 27-29': r'(?:CA\s?27\-29|ca\s?27\-29|CA2729|ca2729)[\s\:]*([0-9]+\.?[0-9]*)',
        'CYFRA 21-1': r'(?:CYFRA\s?21\-1|cyfra\s?21\-1|cytokeratin)[\s\:]*([0-9]+\.?[0-9]*)',
        'NSE': r'(?:NSE|nse|neuron.*?specific|nöron.*?spesifik)[\s\:]*([0-9]+\.?[0-9]*)'
    }
    
    # Her satırı kontrol et
    for line in lines:
        line_lower = line.lower()
        for param_name, pattern in parameter_patterns.items():
            match = re.search(pattern, line_lower, re.IGNORECASE)
            if match:
                try:
                    value = float(match.group(1))
                    extracted_params[param_name] = value
                except (ValueError, IndexError):
                    continue
    
    return extracted_params

def categorize_parameters(extracted_params):
    """Parametreleri kategorilere ayırır ve hasta dostu açıklamalar ekler"""
    categorized = {}
    
    for category_key, category_data in BLOOD_TEST_PARAMETERS.items():
        category_name = category_data['name']
        category_params = {}
        
        for param_key, param_info in category_data['parameters'].items():
            if param_key in extracted_params:
                value = extracted_params[param_key]
                is_normal = param_info['min'] <= value <= param_info['max']
                
                # Durumu belirle
                if value < param_info['min']:
                    status = "düşük"
                    status_emoji = "⬇️"
                    # Düşük değer açıklaması
                    simple_explanation = param_info.get('low_explanation', 'Bu değer normal aralığın altında')
                    possible_conditions = param_info.get('low_conditions', ['Doktor kontrolü önerilir'])
                elif value > param_info['max']:
                    status = "yüksek" 
                    status_emoji = "⬆️"
                    # Yüksek değer açıklaması
                    simple_explanation = param_info.get('high_explanation', 'Bu değer normal aralığın üstünde')
                    possible_conditions = param_info.get('high_conditions', ['Doktor kontrolü önerilir'])
                else:
                    status = "normal"
                    status_emoji = "✅"
                    simple_explanation = "Bu değer normal aralıkta, harika!"
                    possible_conditions = ["Değer normal, endişe yok"]
                
                category_params[param_key] = {
                    'name': param_info['name'],
                    'value': value,
                    'unit': param_info['unit'],
                    'min': param_info['min'],
                    'max': param_info['max'],
                    'is_normal': is_normal,
                    'status': status,
                    'status_emoji': status_emoji,
                    'description': param_info['description'],
                    'simple_explanation': simple_explanation,
                    'possible_conditions': possible_conditions,
                    'what_is_it': param_info.get('what_is_it', 'Sağlık göstergesi')
                }
        
        if category_params:  # Sadece parametre varsa kategoriyi ekle
            categorized[category_key] = {
                'name': category_name,
                'description': category_data['description'],
                'parameters': category_params
            }
    
    return categorized

def calculate_disease_risks(extracted_params):
    """Hastalık risklerini hesaplar"""
    disease_risks = []
    
    for disease_key, disease_info in DISEASE_RISK_ALGORITHMS.items():
        total_weight = 0
        matching_weight = 0
        
        for condition in disease_info['conditions']:
            param_name = condition['param']
            operator = condition['operator']
            threshold_value = condition['value']
            weight = condition['weight']
            
            if param_name in extracted_params:
                actual_value = extracted_params[param_name]
                total_weight += weight
                
                # Koşulu kontrol et
                condition_met = False
                if operator == '>' and actual_value > threshold_value:
                    condition_met = True
                elif operator == '<' and actual_value < threshold_value:
                    condition_met = True
                elif operator == '>=' and actual_value >= threshold_value:
                    condition_met = True
                elif operator == '<=' and actual_value <= threshold_value:
                    condition_met = True
                
                if condition_met:
                    matching_weight += weight
        
        # Risk yüzdesini hesapla
        if total_weight > 0:
            risk_percentage = int((matching_weight / total_weight) * 100)
            
            # Sadece %15'in üzerindeki riskleri ekle
            if risk_percentage >= 15:
                # Risk seviyesini belirle
                if risk_percentage >= 70:
                    severity = "Yüksek Risk"
                    severity_emoji = "🔴"
                elif risk_percentage >= 40:
                    severity = "Orta Risk"
                    severity_emoji = "🟡"
                else:
                    severity = "Düşük Risk"
                    severity_emoji = "🟢"
                
                disease_risks.append({
                    'name': disease_info['name'],
                    'description': disease_info['description'],
                    'risk_percentage': risk_percentage,
                    'severity': severity,
                    'severity_emoji': severity_emoji,
                    'related_parameters': disease_info['parameters']
                })
    
    # Risk yüzdesine göre sırala
    disease_risks.sort(key=lambda x: x['risk_percentage'], reverse=True)
    
    return disease_risks

# Ödeme API Helper Fonksiyonları (Yeni ödeme sistemi buraya eklenecek)

def generate_detailed_analysis_report(categorized_params, disease_risks, extracted_params):
    """Detaylı analiz raporu oluşturur"""
    report_sections = []
    
    # 1. Genel Değerlendirme
    total_params = sum(len(cat['parameters']) for cat in categorized_params.values())
    abnormal_params = sum(
        len([p for p in cat['parameters'].values() if not p['is_normal']]) 
        for cat in categorized_params.values()
    )
    normal_percentage = int(((total_params - abnormal_params) / total_params) * 100) if total_params > 0 else 0
    
    general_summary = f"""
## 📊 GENEL DEĞERLENDİRME

**Tahlil Özeti:**
- Toplam analiz edilen parametre: {total_params}
- Normal aralıkta olan: {total_params - abnormal_params} ({normal_percentage}%)
- Normal dışı olan: {abnormal_params} ({100 - normal_percentage}%)

**Genel Sağlık Durumu:** """
    
    if normal_percentage >= 90:
        general_summary += "🟢 Mükemmel - Tüm değerleriniz normal aralıkta"
    elif normal_percentage >= 80:
        general_summary += "🟡 İyi - Çoğu değeriniz normal aralıkta, küçük sapmaları takip edin"
    elif normal_percentage >= 60:
        general_summary += "🟠 Orta - Bazı değerler dikkat gerektiriyor, doktor takibi öneriliyor"
    else:
        general_summary += "🔴 Dikkat - Birden fazla değer normal dışı, doktor kontrolü gerekli"
    
    report_sections.append(general_summary)
    
    # 2. Kategori bazında detaylı analiz
    for category_key, category_data in categorized_params.items():
        section = f"\n## {category_data['name']}\n"
        section += f"_{category_data['description']}_\n\n"
        
        section += "| Test | Sonuç | Normal Aralık | Durum | Yorum |\n"
        section += "|------|-------|---------------|-------|-------|\n"
        
        for param_key, param_data in category_data['parameters'].items():
            ref_range = f"{param_data['min']} - {param_data['max']} {param_data['unit']}"
            value_with_unit = f"{param_data['value']} {param_data['unit']}"
            status_text = f"{param_data['status_emoji']} {param_data['status'].title()}"
            
            # Yorum oluştur
            if param_data['is_normal']:
                comment = "Normal değer"
            else:
                if param_data['status'] == "yüksek":
                    comment = f"Normal üstü - {param_data['description']}"
                else:
                    comment = f"Normal altı - {param_data['description']}"
            
            section += f"| {param_data['name']} | {value_with_unit} | {ref_range} | {status_text} | {comment} |\n"
        
        # Kategori yorumu
        abnormal_in_category = [p for p in category_data['parameters'].values() if not p['is_normal']]
        if abnormal_in_category:
            section += f"\n**🔸 {category_data['name']} Yorumu:**\n"
            for param in abnormal_in_category:
                if param['status'] == "yüksek":
                    section += f"- **{param['name']}** yüksek: Bu değer {param['description'].lower()}\n"
                else:
                    section += f"- **{param['name']}** düşük: Bu değer {param['description'].lower()}\n"
        else:
            section += f"\n✅ **{category_data['name']}** tüm değerleri normal aralıkta.\n"
        
        report_sections.append(section)
    
    # 3. Hastalık Risk Analizi
    if disease_risks:
        risk_section = "\n## 🎯 OLASI HASTALIK RİSKLERİ\n\n"
        risk_section += "| Hastalık | Risk Oranı | Seviye | İlgili Değerler |\n"
        risk_section += "|----------|------------|--------|------------------|\n"
        
        for risk in disease_risks:
            related_params = ", ".join(risk['related_parameters'])
            risk_section += f"| {risk['name']} | %{risk['risk_percentage']} | {risk['severity_emoji']} {risk['severity']} | {related_params} |\n"
        
        risk_section += "\n**🔸 Risk Açıklamaları:**\n"
        for risk in disease_risks:
            risk_section += f"- **{risk['name']} (%{risk['risk_percentage']}):** {risk['description']}\n"
        
        report_sections.append(risk_section)
    
    # 4. Öneriler
    recommendations = "\n## 💡 ÖNERİLER\n\n"
    
    # Genel öneriler
    if abnormal_params > 0:
        recommendations += "**Genel Öneriler:**\n"
        recommendations += "- Anormal bulunan değerler için doktor kontrolü yaptırın\n"
        recommendations += "- Düzenli takip ile değerlerin değişimini izleyin\n"
        recommendations += "- Yaşam tarzı değişiklikleri ile iyileştirme sağlanabilir\n\n"
    
    # Spesifik öneriler
    lifestyle_recommendations = []
    if any('Glucose' in cat['parameters'] and not cat['parameters']['Glucose']['is_normal'] 
           for cat in categorized_params.values() if 'Glucose' in cat['parameters']):
        lifestyle_recommendations.append("🍎 **Beslenme:** Şeker alımını azaltın, kompleks karbonhidrat tercih edin")
    
    if any('Total_Cholesterol' in cat['parameters'] and not cat['parameters']['Total_Cholesterol']['is_normal'] 
           for cat in categorized_params.values() if 'Total_Cholesterol' in cat['parameters']):
        lifestyle_recommendations.append("🫀 **Kalp Sağlığı:** Doymuş yağları azaltın, omega-3 alımını artırın")
    
    if any('HGB' in cat['parameters'] and not cat['parameters']['HGB']['is_normal'] 
           for cat in categorized_params.values() if 'HGB' in cat['parameters']):
        lifestyle_recommendations.append("🥩 **Demir:** Demir açısından zengin besinler tüketin (kırmızı et, ıspanak)")
    
    if lifestyle_recommendations:
        recommendations += "**Yaşam Tarzı Önerileri:**\n"
        for rec in lifestyle_recommendations:
            recommendations += f"- {rec}\n"
    
    recommendations += "\n**⚠️ Önemli Uyarı:** Bu analiz sadece bilgilendirme amaçlıdır. Kesin tanı ve tedavi için mutlaka bir sağlık profesyoneliyle görüşün."
    
    report_sections.append(recommendations)
    
    return "\n".join(report_sections)

# Veritabanı ayarları
DB_PATH = os.environ.get('DB_PATH', 'kan_tahlil_app.db')

# Ödeme Sistemi Konfigürasyonu (Yeni ödeme sistemi buraya eklenecek)



def init_db():
    """Veritabanını ve tabloları oluşturur"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Veritabanının mevcut olup olmadığını kontrol et
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
    table_exists = c.fetchone()
    
    if not table_exists:
        # Kullanıcılar tablosu - şifre kolonu için daha fazla alan
        c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT 1,
            role TEXT DEFAULT 'user',
            login_count INTEGER DEFAULT 0,
            subscription_plan TEXT DEFAULT 'free',
            stripe_customer_id TEXT,
            subscription_status TEXT DEFAULT 'active',
            subscription_end_date TIMESTAMP
        )
        ''')
        
        # Tahlil kayıtları tablosu
        c.execute('''
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            file_name TEXT,
            analysis_text TEXT,
            analysis_result TEXT,
            analysis_json TEXT,
            analysis_type TEXT DEFAULT 'kan',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Tahlil değerleri tablosu (yeni)
        c.execute('''
        CREATE TABLE IF NOT EXISTS test_values (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER,
            parameter_name TEXT,
            value REAL,
            unit TEXT,
            ref_min REAL,
            ref_max REAL,
            is_normal BOOLEAN,
            category TEXT,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (analysis_id) REFERENCES analyses (id) ON DELETE CASCADE
        )
        ''')
        
        # Abonelikler tablosu
        c.execute('''
        CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            plan_type TEXT NOT NULL,
            stripe_subscription_id TEXT,
            stripe_customer_id TEXT,
            status TEXT NOT NULL,
            current_period_start TIMESTAMP,
            current_period_end TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Faturalar tablosu
        c.execute('''
        CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            subscription_id INTEGER,
            stripe_invoice_id TEXT,
            amount REAL,
            currency TEXT DEFAULT 'TRY',
            status TEXT,
            invoice_date TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (subscription_id) REFERENCES subscriptions (id)
        )
        ''')
        
        # Kullanım istatistikleri tablosu
        c.execute('''
        CREATE TABLE IF NOT EXISTS usage_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            analysis_count INTEGER DEFAULT 0,
            month INTEGER,
            year INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        ''')
        
        # Newsletter aboneleri tablosu
        c.execute('''
        CREATE TABLE IF NOT EXISTS newsletter_subscribers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            status TEXT DEFAULT 'active',
            source TEXT DEFAULT 'website',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        ''')
    else:
        # Kullanıcı tablosunu güncelle (abonelik alanları ekle)
        c.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in c.fetchall()]
        
        # Yeni sütunları kontrol et ve ekle
        if 'subscription_plan' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN subscription_plan TEXT DEFAULT 'free'")
        
        if 'stripe_customer_id' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN stripe_customer_id TEXT")
        
        if 'subscription_status' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN subscription_status TEXT DEFAULT 'active'")
        
        if 'subscription_end_date' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN subscription_end_date TIMESTAMP")
        
        if 'lemonsqueezy_subscription_id' not in columns:
            c.execute("ALTER TABLE users ADD COLUMN lemonsqueezy_subscription_id TEXT")
        
        # Abonelikler tablosunu kontrol et ve oluştur
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'")
        if not c.fetchone():
            c.execute('''
            CREATE TABLE subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                plan_type TEXT NOT NULL,
                stripe_subscription_id TEXT,
                stripe_customer_id TEXT,
                status TEXT NOT NULL,
                current_period_start TIMESTAMP,
                current_period_end TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')
        
        # Faturalar tablosunu kontrol et ve oluştur
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='invoices'")
        if not c.fetchone():
            c.execute('''
            CREATE TABLE invoices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                subscription_id INTEGER,
                stripe_invoice_id TEXT,
                amount REAL,
                currency TEXT DEFAULT 'TRY',
                status TEXT,
                invoice_date TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (subscription_id) REFERENCES subscriptions (id)
            )
            ''')
        
        # Kullanım istatistikleri tablosunu kontrol et ve oluştur
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='usage_stats'")
        if not c.fetchone():
            c.execute('''
            CREATE TABLE usage_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                analysis_count INTEGER DEFAULT 0,
                month INTEGER,
                year INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
            ''')
        
        # Newsletter aboneleri tablosunu kontrol et ve oluştur
        c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='newsletter_subscribers'")
        if not c.fetchone():
            c.execute('''
            CREATE TABLE newsletter_subscribers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'active',
                source TEXT DEFAULT 'website',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')

    # Admin kullanıcısını kontrol et ve ekle
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    admin = c.fetchone()
    
    if not admin:
        # Admin kullanıcısını oluştur
        admin_password = hash_password("admin123")
        c.execute("INSERT INTO users (username, password, email, role) VALUES (?, ?, ?, ?)", 
                 ("admin", admin_password, "admin@meditahlil.com", "admin"))
        print("Admin kullanıcısı oluşturuldu. Kullanıcı adı: admin, Şifre: admin123")
    
    conn.commit()
    conn.close()

# Şifre işlemleri için yardımcı fonksiyonlar
def hash_password(password):
    """Şifreyi güvenli bir şekilde hash'ler"""
    # Şifreyi önce encode edip byte dizisine dönüştürüyoruz, sonra hash'leyip string olarak saklıyoruz
    password_bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode('utf-8')  # Veritabanında string olarak saklamak için decode ediyoruz

def check_password(hashed_password, user_password):
    """Kullanıcının girdiği şifreyi hash'lenmiş şifre ile karşılaştırır"""
    try:
        # Veritabanından gelen string hash'i byte dizisine çeviriyoruz
        hashed_bytes = hashed_password.encode('utf-8')
        user_bytes = user_password.encode('utf-8')
        return bcrypt.checkpw(user_bytes, hashed_bytes)
    except ValueError:
        # Salt hatası durumunda False döndür - güvenlik için
        return False

# Email konfigürasyonu config.py'dan geldi

def send_email_async(to_email, subject, html_content, plain_content=None):
    """Asenkron email gönderme"""
    def send_email():
        try:
            # Demo mod kontrolü - eğer gerçek email ayarları yoksa console'a yazdır
            if not EMAIL_SETTINGS['EMAIL_PASSWORD']:
                print("\n" + "="*80)
                print("📧 EMAIL GÖNDERILDI (DEMO MOD)")
                print("="*80)
                print(f"Alıcı: {to_email}")
                print(f"Konu: {subject}")
                print(f"Gönderen: {EMAIL_SETTINGS['FROM_NAME']} <{EMAIL_SETTINGS['EMAIL_ADDRESS']}>")
                print("-"*80)
                print("PLAIN TEXT İÇERİK:")
                print(plain_content if plain_content else "Plain text içerik yok")
                print("-"*80)
                print("HTML İÇERİK BAŞLIKLARI:")
                print("✓ MedikalAI Hoş Geldin Emaili")
                print("✓ Gradient Header ile Professional Tasarım")
                print("✓ Özellik Listesi ve CTA Buttonları")
                print("✓ Yasal Uyarılar ve Abonelik İptal Linki")
                print("="*80)
                app.logger.info(f"Email gönderildi (DEMO): {to_email}")
                return
            
            # Gerçek email gönderimi
            msg = MIMEMultipart('alternative')
            msg['From'] = f"{EMAIL_SETTINGS['FROM_NAME']} <{EMAIL_SETTINGS['EMAIL_ADDRESS']}>"
            msg['To'] = to_email
            msg['Subject'] = subject

            # Plain text version (fallback)
            if plain_content:
                part1 = MIMEText(plain_content, 'plain', 'utf-8')
                msg.attach(part1)

            # HTML version
            part2 = MIMEText(html_content, 'html', 'utf-8')
            msg.attach(part2)

            # SMTP bağlantısı kur ve gönder
            server = smtplib.SMTP(EMAIL_SETTINGS['SMTP_SERVER'], EMAIL_SETTINGS['SMTP_PORT'])
            server.starttls()
            server.login(EMAIL_SETTINGS['EMAIL_ADDRESS'], EMAIL_SETTINGS['EMAIL_PASSWORD'])
            
            text = msg.as_string()
            server.sendmail(EMAIL_SETTINGS['EMAIL_ADDRESS'], to_email, text)
            server.quit()
            
            app.logger.info(f"Email başarıyla gönderildi: {to_email}")
            
        except Exception as e:
            app.logger.error(f"Email gönderme hatası: {str(e)}")

    # Email'i arka planda gönder
    thread = threading.Thread(target=send_email)
    thread.daemon = True
    thread.start()

def get_welcome_email_template(email):
    """Hoş geldin email template'i"""
    html_template = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>MedikalAI'ya Hoş Geldiniz!</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f4f4;
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background-color: #ffffff;
                box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
            }}
            .header {{
                background: linear-gradient(135deg, #33baf7 0%, #1e3a8a 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }}
            .header h1 {{
                margin: 0;
                font-size: 28px;
                font-weight: bold;
            }}
            .header p {{
                margin: 10px 0 0 0;
                font-size: 16px;
                opacity: 0.9;
            }}
            .content {{
                padding: 40px 30px;
            }}
            .welcome-text {{
                font-size: 18px;
                line-height: 1.6;
                color: #333;
                margin-bottom: 30px;
            }}
            .features {{
                background-color: #f8f9fa;
                padding: 25px;
                border-radius: 8px;
                margin: 25px 0;
            }}
            .features h3 {{
                color: #33baf7;
                font-size: 20px;
                margin: 0 0 15px 0;
            }}
            .feature-list {{
                list-style: none;
                padding: 0;
                margin: 0;
            }}
            .feature-list li {{
                padding: 8px 0;
                font-size: 16px;
                color: #555;
            }}
            .feature-list li:before {{
                content: "✓";
                color: #33baf7;
                font-weight: bold;
                margin-right: 10px;
            }}
            .cta-button {{
                display: inline-block;
                background: linear-gradient(135deg, #33baf7 0%, #1e3a8a 100%);
                color: white;
                padding: 15px 30px;
                text-decoration: none;
                border-radius: 5px;
                font-weight: bold;
                margin: 20px 0;
            }}
            .footer {{
                background-color: #2c3e50;
                color: white;
                padding: 30px;
                text-align: center;
                font-size: 14px;
            }}
            .footer a {{
                color: #33baf7;
                text-decoration: none;
            }}
            .disclaimer {{
                background-color: #fff3cd;
                border: 1px solid #ffeaa7;
                padding: 15px;
                border-radius: 5px;
                margin: 20px 0;
                font-size: 14px;
                color: #856404;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🧠 MedikalAI</h1>
                <p>Sağlık Rehberinize Hoş Geldiniz!</p>
            </div>
            
            <div class="content">
                <div class="welcome-text">
                    Merhaba,<br><br>
                    
                    <strong>MedikalAI Sağlık Rehberi</strong>'ne abone olduğunuz için teşekkür ederiz! 🎉
                    <br><br>
                    
                    Artık en güncel sağlık bilgileri, kan tahlili yorumlama ipuçları ve özel içerikleri doğrudan e-posta kutunuza gelecek.
                </div>
                
                <div class="features">
                    <h3>📧 Ne Tür İçerikler Alacaksınız?</h3>
                    <ul class="feature-list">
                        <li>Kan tahlili değerleri ve yorumları</li>
                        <li>Sağlık parametrelerinizi anlama rehberleri</li>
                        <li>Beslenme ve yaşam tarzı önerileri</li>
                        <li>En yeni tıbbi gelişmeler ve araştırmalar</li>
                        <li>MedikalAI platformu güncellemeleri</li>
                        <li>Özel indirimler ve erken erişim fırsatları</li>
                    </ul>
                </div>
                
                <div style="text-align: center;">
                    <a href="http://localhost:8080/blog" class="cta-button">
                        📖 Sağlık Rehberini Keşfedin
                    </a>
                </div>
                
                <div class="disclaimer">
                    <strong>⚠️ Önemli Uyarı:</strong> MedikalAI içerikleri sadece bilgilendirme amaçlıdır. 
                    Sağlık sorunlarınız için mutlaka bir sağlık profesyoneliyle görüşün.
                </div>
                
                <p style="color: #666; font-size: 14px; margin-top: 30px;">
                    Bu e-postayı <strong>{email}</strong> adresine gönderdik çünkü MedikalAI newsletter'ına abone oldunuz.
                    <br><br>
                    Artık almak istemiyorsanız, 
                    <a href="http://localhost:8080/newsletter/unsubscribe?email={email}" style="color: #33baf7;">
                        buradan aboneliğinizi iptal edebilirsiniz
                    </a>.
                </p>
            </div>
            
            <div class="footer">
                <strong>MedikalAI</strong><br>
                Yapay Zeka Destekli Sağlık Platformu<br><br>
                
                📧 info@medikalai.com | 📞 +90 539 394 90 35<br>
                🌐 <a href="http://localhost:8080">medikalai.com</a>
                
                <p style="margin-top: 20px; opacity: 0.8;">
                    © 2025 MedikalAI. Tüm hakları saklıdır.
                </p>
            </div>
        </div>
    </body>
    </html>
    """
    
    plain_text = f"""
    MedikalAI Sağlık Rehberi'ne Hoş Geldiniz!
    
    Merhaba,
    
    MedikalAI newsletter'ına abone olduğunuz için teşekkür ederiz!
    
    Artık şunları e-posta kutunuzda alacaksınız:
    - Kan tahlili değerleri ve yorumları
    - Sağlık rehberleri
    - Beslenme önerileri
    - Tıbbi gelişmeler
    - Platform güncellemeleri
    
    Sağlık rehberini keşfetmek için: http://localhost:8080/blog
    
    Bu e-posta {email} adresine gönderildi.
    Aboneliği iptal etmek için: http://localhost:8080/newsletter/unsubscribe?email={email}
    
    MedikalAI Ekibi
    info@medikalai.com
    """
    
    return html_template, plain_text

# Admin gerekli dekoratör
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfayı görüntülemek için giriş yapmalısınız!', 'warning')
            return redirect(url_for('login'))
        
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            c = conn.cursor()
            c.execute("SELECT role FROM users WHERE id = ?", (session['user_id'],))
            user = c.fetchone()
            conn.close()
            
            if not user or user['role'] != 'admin':
                flash('Bu sayfaya erişim yetkiniz bulunmamaktadır!', 'danger')
                return redirect(url_for('dashboard'))
                
        except Exception as e:
            app.logger.error(f"Admin yetkisi kontrolünde hata: {str(e)}")
            flash('Bir hata oluştu. Lütfen tekrar giriş yapın.', 'danger')
            return redirect(url_for('login'))
            
        return f(*args, **kwargs)
    return decorated_function

# Yeni kullanıcı kontrolü
def is_new_user(user_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    analysis_count = c.execute('SELECT COUNT(*) FROM analyses WHERE user_id = ?', (user_id,)).fetchone()[0]
    login_count = c.execute('SELECT login_count FROM users WHERE id = ?', (user_id,)).fetchone()[0]
    conn.close()
    
    # Eğer kullanıcı ilk kez giriş yaptıysa veya hiç analizi yoksa yeni kullanıcı olarak kabul et
    return analysis_count == 0 or login_count <= 2

# Kullanıcının giriş sayısını arttır
def increment_login_count(user_id):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('UPDATE users SET login_count = login_count + 1 WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Ana sayfa"""
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f"Ana sayfa yüklenirken hata: {str(e)}")
        return "MedikalAI uygulaması çalışıyor! Ana sayfa yüklenemiyor, lütfen <a href='/login'>giriş sayfasına</a> gidin."

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Kullanıcı girişi"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT id, username, password, role FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password(user['password'], password):
            # JWT token oluştur
            access_token = create_access_token(identity=user['id'])
            
            # Session'a kullanıcı bilgilerini kaydet
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['jwt_token'] = access_token
            
            # Kullanıcının giriş sayısını artır
            increment_login_count(user['id'])
            
            flash('Başarıyla giriş yaptınız!', 'success')
            
            # Admin kullanıcısı ise admin paneline yönlendir
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('dashboard'))
        else:
            flash('Kullanıcı adı veya şifre hatalı!', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """Yeni kullanıcı kaydı"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        email = request.form['email']
        
        # Form doğrulama
        if not username or not password or not email:
            flash('Tüm alanlar doldurulmalıdır!', 'danger')
            return render_template('register.html')
            
        if len(password) < 6:
            flash('Şifre en az 6 karakter olmalıdır!', 'danger')
            return render_template('register.html')
        
        # Şifreyi hashle
        hashed_password = hash_password(password)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                     (username, hashed_password, email))
            conn.commit()
            flash('Kaydınız başarıyla oluşturuldu! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Bu kullanıcı adı veya e-posta zaten kullanılıyor!', 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    """Kullanıcı çıkışı"""
    session.clear()
    flash('Çıkış yaptınız!', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Kullanıcı dashboard sayfası"""
    if 'user_id' not in session:
        flash('Bu sayfayı görüntülemek için giriş yapmalısınız!', 'warning')
        return redirect(url_for('login'))
    
    # Kullanıcının geçmiş analizlerini getir
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM analyses WHERE user_id = ? ORDER BY created_at DESC", (session['user_id'],))
    analyses = c.fetchall()
    conn.close()
    
    return render_template('dashboard.html', analyses=analyses)

@app.route('/analyze', methods=['GET', 'POST'])
def analyze():
    """PDF tahlil analizi"""
    if 'user_id' not in session:
        flash('Tahlil yüklemek için giriş yapmalısınız!', 'warning')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    try:
        # Kullanıcı bilgilerini al
        c.execute("SELECT subscription_plan, role FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        current_plan = user['subscription_plan'] if user else 'free'
        user_role = user['role'] if user else 'user'
        
        # Admin kullanıcıları için sınırsız yetki
        if user_role == 'admin':
            plan_name = "Admin (Sınırsız)"
            analysis_limit = float('inf')
            remaining_analyses = 999
        else:
            # Plan bilgilerini al
            plan_name = SUBSCRIPTION_PLANS[current_plan]['name']
            analysis_limit = SUBSCRIPTION_PLANS[current_plan]['analysis_limit']
            
            if analysis_limit == float('inf'):
                remaining_analyses = 999
            else:
                current_month = datetime.now().month
                current_year = datetime.now().year
                c.execute("""
                    SELECT COUNT(*) as count FROM analyses 
                    WHERE user_id = ? 
                    AND strftime('%m', created_at) = ? 
                    AND strftime('%Y', created_at) = ?
                """, (session['user_id'], f"{current_month:02d}", str(current_year)))
                monthly_count = c.fetchone()['count']
                remaining_analyses = max(0, analysis_limit - monthly_count)
        
        if request.method == 'POST':
            # Admin kontrolü - adminler için limit yok
            if user_role != 'admin' and remaining_analyses <= 0 and current_plan not in ['premium', 'family']:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": "Bu ay için tahlil hakkınız dolmuştur."}), 400
                flash('Bu ay için tahlil hakkınız dolmuştur.', 'warning')
                return redirect(url_for('subscription_plans'))
            
            file = request.files.get('pdf_file')
            if not file or not file.filename.lower().endswith('.pdf'):
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": "Lütfen bir PDF dosyası yükleyin."}), 400
                flash('Lütfen bir PDF dosyası yükleyin.', 'danger')
                return redirect(url_for('analyze'))

            # Son 30 saniye içinde aynı dosya adıyla yükleme yapılmış mı kontrol et
            c.execute("""
                SELECT id FROM analyses 
                WHERE user_id = ? 
                AND file_name = ? 
                AND created_at >= datetime('now', '-30 seconds')
            """, (session['user_id'], file.filename))
            
            recent_upload = c.fetchone()
            if recent_upload:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": "Aynı dosya kısa süre önce yüklendi. Lütfen biraz bekleyin."}), 400
                flash('Aynı dosya kısa süre önce yüklendi. Lütfen biraz bekleyin.', 'warning')
                return redirect(url_for('analyze'))

            # Dosya boyutu kontrolü (10MB)
            if len(file.read()) > 10 * 1024 * 1024:  # 10MB
                file.seek(0)  # Dosya işaretçisini başa al
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": "Dosya boyutu 10MB'dan büyük olamaz."}), 400
                flash('Dosya boyutu 10MB\'dan büyük olamaz.', 'danger')
                return redirect(url_for('analyze'))
            
            file.seek(0)  # Dosya işaretçisini tekrar başa al

            try:
                pdf_reader = PyPDF2.PdfReader(BytesIO(file.read()))
                text = "\n".join(page.extract_text() or '' for page in pdf_reader.pages)
                if not text.strip():
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({"error": "PDF'den metin okunamadı."}), 400
                    flash('PDF\'den metin okunamadı.', 'danger')
                    return redirect(url_for('analyze'))
            except Exception as e:
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": f"PDF okunamadı: {e}"}), 400
                flash(f'PDF okunamadı: {e}', 'danger')
                return redirect(url_for('analyze'))
            
            # Yeni gelişmiş analiz sistemi
            try:
                # 1. PDF'den parametreleri çıkar
                extracted_params = parse_blood_test_from_text(text)
                print(f"[Analiz] Çıkarılan parametreler: {list(extracted_params.keys())}")
                
                # 2. Parametreleri kategorilere ayır
                categorized_params = categorize_parameters(extracted_params)
                print(f"[Analiz] Kategoriler: {list(categorized_params.keys())}")
                
                # 3. Hastalık risklerini hesapla
                disease_risks = calculate_disease_risks(extracted_params)
                print(f"[Analiz] Tespit edilen risk sayısı: {len(disease_risks)}")
                
                # 4. Detaylı rapor oluştur
                detailed_report = generate_detailed_analysis_report(categorized_params, disease_risks, extracted_params)
                
                # Eğer parametreler bulunamadıysa veya çok az ise, Gemini ile analiz yap
                if len(extracted_params) < 3:
                    print("[Analiz] Yeterli parametre bulunamadı, Gemini analizi yapılıyor...")
                    
                    # Fallback: Gemini analizi
                    prompt = f"""Bir doktor gibi aşağıdaki kan tahlili raporunu kategorilere ayırarak analiz et:

🧬 1. Kanser Göstergeleri (Tümör Belirteçleri) - CEA, CA 15-3, PSA vb.
🩸 2. Tam Kan Sayımı (Hemogram) - WBC, HGB, HCT, PLT vb.
⚖️ 3. Elektrolitler ve Mineraller - Na, K, Ca, Mg vb.
🫘 4. Böbrek Fonksiyonları - Üre, Kreatinin, eGFR vb.
🍃 5. Karaciğer Fonksiyonları - ALT, AST, GGT vb.
🍬 6. Pankreas ve Enzimler - Amilaz, Lipaz vb.
🍭 7. Şeker ve Metabolizma - Glukoz, HbA1c vb.
🫀 8. Lipid Profili - Kolesterol, LDL, HDL vb.
🧪 9. Hormonlar - TSH, T3, T4 vb.
🔥 10. İnflamasyon - CRP, ESR vb.

Her kategori için:
- Parametre adı, sonuç, normal aralık
- ✅ Normal, ⚠️ Hafif anormal, 🔴 Ciddi anormal
- Açıklayıcı yorum

Sonunda:
📋 SONUÇ ÖZETİ tablosu
🎯 OLASI HASTALIKLAR (%risk oranı ile)

Hasta dostu Türkçe kullan, tıbbi terimler için açıklama ekle.

KAN TAHLİLİ:
{text[:4000]}"""
                    
                    # Gemini API'yi çağır
                    data = {
                        "contents": [{"parts": [{"text": prompt}]}],
                        "generationConfig": {
                            "temperature": 0.8,
                            "maxOutputTokens": 8000,
                            "topP": 0.95,
                            "topK": 40
                        }
                    }
                    
                    headers = {"Content-Type": "application/json"}
                    response = requests.post(GEMINI_API_URL, headers=headers, json=data, timeout=30)
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        if "candidates" in response_data and response_data["candidates"]:
                            gemini_result = response_data["candidates"][0]["content"]["parts"][0]["text"]
                            result_text = gemini_result
                        else:
                            result_text = detailed_report
                    else:
                        result_text = detailed_report
                else:
                    # Yeterli parametre varsa, detaylı raporu kullan
                    result_text = detailed_report
                
                print(f"[Analiz] Rapor oluşturuldu, uzunluk: {len(result_text)} karakter")
                
            except Exception as e:
                print(f"[Analiz] Gelişmiş analiz hatası: {str(e)}, Gemini fallback kullanılıyor...")
                
                # Hata durumunda Gemini'ye geri dön
                prompt = f"""Bir doktor gibi aşağıdaki kan tahlili raporunu hastanın anlaması için sade bir Türkçe dille tıbbi terimleri açıklayarak yorumla.
                
Lütfen şunları yap:
1. Tüm önemli değerleri ve referans aralıklarını analiz et
2. Normal dışı değerleri belirle ve hastanın anlayacağı tıbbi terimleri açıkla
3. Değerlere bakarak muhtemel sağlık durumları veya olası hastalık belirtilerinden bahset
4. Bulgulara dayalı öneriler sun ve hangi branştan doktora danışılması gerektiğini belirt
5. Değerleri anlamlı gruplara ayır (örn: hematoloji, biyokimya, vb.)
6. Yaşam tarzı ve beslenme önerileri ekle
7. Gerekirse ek tetkik önerilerini gerekçeleriyle açıkla

Değerlendirmede şunlara dikkat et:
1. Bir tıp doktoru gibi analiz et ama anlatımını sade ve hasta dostu bir dille yap
2. Tıbbi terimleri kullandığında parantez içinde basit açıklamalarını ekle
3. Değerlerin insan vücudundaki işlevlerini basit ve kısa bir şekilde anlat
4. Anormal değerlere özel vurgu yap ve bunların ne anlama gelebileceğini detaylıca açıkla
5. Olası hastalıklar veya durumları olasılık derecesiyle birlikte açıkla
6. Değerlere göre kişiselleştirilmiş yaşam tarzı önerileri ver
7. Ne zaman ve hangi uzmana başvurulması gerektiğini belirt

Cevabının şu bölümleri içermesini istiyorum:
- GENEL DEĞERLENDİRME: Tahlil sonuçlarının genel bir özeti
- NORMAL DIŞI DEĞERLER: Normal olmayan değerleri ve anlamlarını açıkla
- OLASI SAĞLIK DURUMLARI: Olası sağlık durumları ve açıklamaları
- ÖNERİLER: Tahlil sonuçlarına göre öneriler
- YAŞAM TARZI ÖNERİLERİ: Beslenme, aktivite vs ile ilgili öneriler

KAN TAHLİLİ RAPORU:
{text[:4000]}"""
                
                # Gemini API isteği için veri yapısı
                data = {
                    "contents": [
                        {
                            "parts": [
                                {
                                    "text": prompt
                                }
                            ]
                        }
                    ],
                    "generationConfig": {
                        "temperature": 0.8,
                        "maxOutputTokens": 8000,
                        "topP": 0.95,
                        "topK": 40
                    }
                }
                
                # Gemini API isteği
                headers = {
                    "Content-Type": "application/json",
                    "X-Requested-With": "XMLHttpRequest"  # API'ye AJAX isteği olduğunu bildir
                }
                
                # API isteği gönderiliyor
                print(f"[Fallback] Gemini API'ye istek gönderiliyor: {GEMINI_API_URL}")    
                response = requests.post(
                    GEMINI_API_URL,
                    headers=headers,
                    json=data,
                    timeout=30  # Zaman aşımını 30 saniyeye ayarlıyoruz
                )
                
                if response.status_code == 200:
                    response_data = response.json()
                    if "candidates" in response_data and response_data["candidates"]:
                        result_text = response_data["candidates"][0]["content"]["parts"][0]["text"]
                    else:
                        result_text = "Analiz başarısız oldu. Lütfen tekrar deneyin."
                else:
                    result_text = f"API hatası: HTTP {response.status_code}"
            
            try:
                # Ana analiz işlemi tamamlandı, şimdi veritabanına kaydet
                    
                # Yanıt boş mu kontrol et
                if not result_text or not result_text.strip():
                    print("Analiz sonucu boş")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({"error": "Analiz sonucu boş. Lütfen tekrar deneyin."}), 500
                    flash('Analiz sonucu boş. Lütfen tekrar deneyin.', 'danger')
                    return redirect(url_for('analyze'))
                    
                # Veritabanına kaydetme işlemi
                try:
                    # Metni paragraf ve bölümlere ayır
                    sections = {}
                    current_section = "Genel Değerlendirme"
                    section_text = []
                    
                    for line in result_text.split('\n'):
                        stripped_line = line.strip()
                        if stripped_line and (stripped_line.isupper() or stripped_line.startswith('#') or stripped_line.endswith(':')):
                            # Yeni bir bölüm başlangıcı
                            if section_text:
                                sections[current_section] = '\n'.join(section_text)
                                section_text = []
                            
                            # Başlık formatını temizle
                            current_section = stripped_line.replace('#', '').strip(':').strip()
                        elif stripped_line:
                            section_text.append(stripped_line)
                    
                    # Son bölümü ekle
                    if section_text:
                        sections[current_section] = '\n'.join(section_text)
                    
                    # Normal ve anormal değerleri belirlemek için metin analizi
                    abnormal_values = []
                    
                    if "ANORMAL DEĞERLERİ" in sections or "NORMAL DIŞI DEĞERLER" in sections:
                        abnormal_section = sections.get("ANORMAL DEĞERLERİ", sections.get("NORMAL DIŞI DEĞERLER", ""))
                        for line in abnormal_section.split('\n'):
                            if ":" in line:
                                param_name = line.split(":")[0].strip()
                                abnormal_values.append({"parameter_name": param_name, "description": line})
                    
                    # Veritabanına kaydet
                    conn = sqlite3.connect(DB_PATH)
                    c = conn.cursor()
                    
                    # Ana analizi kaydet
                    c.execute(
                        """INSERT INTO analyses 
                        (user_id, file_name, analysis_text, analysis_result, analysis_type) 
                        VALUES (?, ?, ?, ?, ?)""",
                        (session['user_id'], file.filename, text[:1000], result_text, 'kan')
                    )
                    conn.commit()
                    analysis_id = c.lastrowid
                    
                    # Gelişmiş analiz JSON'ı oluştur
                    analysis_json = {
                        "summary": sections.get("Genel Değerlendirme", result_text[:500]),
                        "abnormal_count": len(abnormal_values),
                        "test_groups": [],
                        "recommendations": sections.get("ÖNERİLER", "").split('\n') if "ÖNERİLER" in sections else [],
                        "lifestyle_advice": sections.get("YAŞAM TARZI ÖNERİLERİ", "").split('\n') if "YAŞAM TARZI ÖNERİLERİ" in sections else [],
                        "health_conditions": [],
                        "general_analysis": result_text,
                        "extracted_parameters": extracted_params if 'extracted_params' in locals() else {},
                        "categorized_data": categorized_params if 'categorized_params' in locals() else {},
                        "disease_risks": disease_risks if 'disease_risks' in locals() else []
                    }
                        
                    # Olası sağlık durumlarını metinden çıkarmaya çalış
                    health_conditions_section = sections.get("OLASI SAĞLIK DURUMLARI", "")
                    if health_conditions_section:
                        # Bölümü satırlara ayır
                        lines = health_conditions_section.split('\n')
                        current_condition = None
                        
                        for line in lines:
                            line = line.strip()
                            if not line:
                                continue
                                
                            # Yeni bir sağlık durumu başlığı
                            if line.endswith(':') or (len(line.split()) <= 5 and not line.startswith('-')):
                                # Önceki durumu kaydet
                                if current_condition:
                                    analysis_json["health_conditions"].append(current_condition)
                                
                                # Yeni durum oluştur
                                name = line.rstrip(':')
                                
                                # Durumun ciddiyetini belirle - artık hepsi "Öneri" olarak işaretlenecek
                                severity = "Öneri"
                                
                                current_condition = {
                                    "name": name,
                                    "description": "",
                                    "severity": severity,
                                    "related_values": ""
                                }
                            # Mevcut duruma açıklama ya da ilgili değerler ekleniyor
                            elif current_condition:
                                if "değer" in line.lower() or "parametre" in line.lower():
                                    # Bu ilgili değerler
                                    values = line.split(":")[-1].strip() if ":" in line else line
                                    current_condition["related_values"] = values
                                else:
                                    # Bu açıklama
                                    if current_condition["description"]:
                                        current_condition["description"] += " " + line
                                    else:
                                        current_condition["description"] = line
                    
                        # Son durumu da ekle
                        if current_condition:
                            analysis_json["health_conditions"].append(current_condition)
                    
                    # Eğer olası sağlık durumları tespit edilemediyse, anormal değerlerden genel öneriler oluştur
                    if not analysis_json["health_conditions"] and abnormal_values:
                        for abnormal in abnormal_values:
                            param_name = abnormal["parameter_name"]
                            description = abnormal["description"]
                            
                            # Genel bir öneri oluştur
                            condition_name = "Genel Sağlık Önerisi"
                            
                            # İlgili değerleri belirle
                            related_values = param_name
                            
                            analysis_json["health_conditions"].append({
                                "name": condition_name,
                                "description": f"Bu değerle ilgili genel sağlık önerisi: {description}",
                                "severity": "Öneri",
                                "related_values": related_values
                            })
                    
                    # JSON'ı veritabanına kaydet
                    c.execute(
                        """UPDATE analyses 
                        SET analysis_json = ? 
                        WHERE id = ?""",
                        (json.dumps(analysis_json), analysis_id)
                    )
                    conn.commit()
                    conn.close()
                    
                    # Ajax isteği ise JSON yanıt döndür
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({
                            "success": True,
                            "message": "Tahlil başarıyla analiz edildi!",
                            "analysis_id": analysis_id,
                            "redirect": url_for('analysis_result', analysis_id=analysis_id)
                        })
                    
                    # Başarı mesajı göster
                    flash('Tahlil başarıyla analiz edildi!', 'success')
                    return redirect(url_for('analysis_result', analysis_id=analysis_id))
                
                except Exception as e:
                    # Veritabanı hatası durumunda
                    print(f"Veritabanı hatası: {str(e)}")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({"error": f"Veritabanı hatası: {str(e)}"}), 500
                    flash(f'Veritabanı hatası: {str(e)}', 'danger')
                    return redirect(url_for('analyze'))
                
            except requests.exceptions.Timeout:
                print("API isteği zaman aşımına uğradı")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": "API isteği zaman aşımına uğradı. Lütfen tekrar deneyin."}), 504
                flash('API isteği zaman aşımına uğradı. Lütfen tekrar deneyin.', 'danger')
                return redirect(url_for('analyze'))
            except Exception as e:
                print(f"Hata oluştu: {str(e)}")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return jsonify({"error": f"Yorum alınamadı: {str(e)}"}), 500
                flash(f'Yorum alınamadı: {e}', 'danger')
                return redirect(url_for('analyze'))
    
    except Exception as e:
        app.logger.error(f"Tahlil analizinde hata: {str(e)}")
        flash(f'Tahlil analizinde bir hata oluştu: {str(e)}', 'danger')
        return redirect(url_for('analyze'))
    
    return render_template('analyze.html',
                         current_plan=current_plan,
                         plan_name=plan_name,
                         analysis_limit=analysis_limit,
                         remaining_analyses=remaining_analyses)

@app.route('/analysis/<int:analysis_id>')
def analysis_result(analysis_id):
    """Analiz sonucu görüntüleme"""
    if 'user_id' not in session:
        flash('Bu sayfayı görüntülemek için giriş yapmalısınız!', 'warning')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Ana analiz bilgilerini getir
    c.execute("SELECT * FROM analyses WHERE id = ? AND user_id = ?", (analysis_id, session['user_id']))
    analysis = c.fetchone()
    
    if not analysis:
        flash('Analiz bulunamadı veya bu analizi görüntüleme yetkiniz yok!', 'danger')
        return redirect(url_for('dashboard'))
    
    # Tahlil sonucu null ise hata mesajı göster
    if not analysis['analysis_result']:
        flash('Tahlil sonucu bulunamadı veya işlenemedi. Lütfen yeni bir tahlil yükleyin.', 'warning')
        return redirect(url_for('dashboard'))
    
    # Analiz JSON'ını parse et
    analysis_json = {}
    if analysis['analysis_json']:
        try:
            analysis_json = json.loads(analysis['analysis_json'])
        except json.JSONDecodeError:
            pass  # JSON parse edilemezse, boş dict kullan
    
    # Anormal değerleri metinden çıkarmaya çalış
    abnormal_values = []
    if analysis_json and 'abnormal_count' in analysis_json and analysis_json['abnormal_count'] > 0:
        # JSON'dan abnormal değer sayısını al
        abnormal_count = analysis_json['abnormal_count']
        
        # Metinden anormal değerleri çıkarmaya çalış
        result_text = analysis['analysis_result']
        lines = result_text.split('\n')
        
        for i, line in enumerate(lines):
            line_lower = line.lower()
            if ('normal değil' in line_lower or 
                'yüksek' in line_lower or 
                'düşük' in line_lower or 
                'anormal' in line_lower or
                'dikkat' in line_lower):
                
                # Değer adını ve açıklamasını çıkarmaya çalış
                parts = line.split(':')
                if len(parts) >= 2:
                    param_name = parts[0].strip()
                    param_desc = parts[1].strip()
                    
                    # Birim ve değer bilgilerini çıkarmaya çalış
                    value_match = None
                    unit_match = None
                    ref_range = None
                    
                    if "(" in param_desc and ")" in param_desc:
                        # Referans aralığı parantez içinde olabilir
                        ref_parts = param_desc.split("(")
                        if len(ref_parts) > 1:
                            ref_range = ref_parts[1].split(")")[0].strip()
                    
                    abnormal_values.append({
                        'parameter_name': param_name,
                        'description': param_desc,
                        'value': value_match if value_match else param_desc.split(" ")[0] if " " in param_desc else "",
                        'unit': unit_match if unit_match else "",
                        'reference_range': ref_range if ref_range else ""
                    })
                else:
                    # Eğer : karakteri yoksa, sadece satırı ekle
                    abnormal_values.append({
                        'parameter_name': 'Anormal Değer',
                        'description': line,
                        'value': "",
                        'unit': "",
                        'reference_range': ""
                    })
    
    # AI ile hastalık tahminlerini getir
    if 'health_conditions' not in analysis_json or not analysis_json.get('health_conditions'):
        # Daha önce AI analizi yapılmamışsa veya boşsa, yeni tahminler al
        health_conditions = analyze_test_results_with_ai(abnormal_values)
        
        # Sonuçları kaydet
        if health_conditions:
            # Mevcut JSON'a ekle
            if not analysis_json:
                analysis_json = {}
            analysis_json['health_conditions'] = health_conditions
            
            # Veritabanında güncelle
            try:
                c.execute("UPDATE analyses SET analysis_json = ? WHERE id = ?", 
                         (json.dumps(analysis_json), analysis_id))
                conn.commit()
            except Exception as e:
                app.logger.error(f"Analiz JSON güncellemesinde hata: {str(e)}")
                conn.rollback()
            else:
            # Zaten AI analizi varsa, onu kullan
                health_conditions = analysis_json.get('health_conditions', [])
    
    # Kullanıcı adını getir (veritabanı kapatılmadan önce)
    c.execute("SELECT username FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    username = user['username'] if user else 'Kullanıcı'
    
    conn.close()
    
    # Kategorize edilmiş verileri ve hastalık risklerini çıkar
    categorized_data = analysis_json.get('categorized_data', {})
    disease_risks = analysis_json.get('disease_risks', [])
    extracted_parameters = analysis_json.get('extracted_parameters', {})
    
    # Şablona bilgileri aktar
    return render_template('result.html', 
                          analysis=analysis,
                          abnormal_values=abnormal_values,
                          analysis_json=analysis_json,
                          test_values=list(extracted_parameters.values()) if extracted_parameters else [],
                          username=username)

# Anormal değerlere göre hastalık tahminleri yapmak için Gemini API fonksiyonu
def analyze_test_results_with_ai(abnormal_values):
    """
    Anormal test değerlerini Gemini API'ye göndererek olası hastalık tahminleri alır
    """
    # Abnormal değerler yoksa bile belirli bilgileri gönder
    if not abnormal_values:
        print("[AI Analiz] Anormal değer yok, ancak genel tahlil analizi isteniyor")
        # Varsayılan metin oluştur
        abnormal_text = "Tahlil sonuçlarında belirgin anormal değer bulunmamaktadır. Ancak normal değerlere bakarak olası riskleri değerlendiriniz."
    else:
        # Abnormal değerleri tek bir metinde birleştir
        abnormal_text = "\n".join([f"{value['parameter_name']}: {value['description']}" for value in abnormal_values])
    
    # Gemini API'ye gönderilecek prompt
    prompt = f"""
    Aşağıdaki kan tahlili sonuçlarıyla ilgili olası hastalık tahminleri yapmanız gerekiyor.
    
    {"Tahlilde normal değerlerin dışında olan parametreler verilmiştir." if abnormal_values else "Tahlil sonuçlarının çoğu normal aralıkta görünmektedir, ancak bu durum bazı gizli veya erken aşama hastalık risklerini dışlamaz."}
    
    Lütfen, anormal değer var ya da yok, HER DURUMDA en az 3, en fazla 5 olası hastalık tahmini ver.
    
    ÖNEMLİ KURALLAR:
    1. "Vitamin D Eksikliği", "Sağlıklı Durum" veya "Hafif Metabolik Değişiklikler" gibi belirsiz durumlar YERİNE, gerçek tıbbi hastalık isimlerini (örn. "Hipotiroidi", "Tip 2 Diyabet", "Demir Eksikliği Anemisi") kullan.
    2. Tahlil sonuçları tamamen normal olsa bile, genel popülasyonda yaygın olan ve erken belirtileri kolayca tespit edilemeyen hastalıklar hakkında bilgi ver.
    3. Her bir tahmin için hastalığın adını, kısa bir açıklamasını ve hangi test değerleriyle ilişkili olduğunu belirt.
    4. Hastalık tahminleri listesi ASLA BOŞ OLMAMALI, mutlaka en az 3 hastalık içermelidir.
    
    Durum:
    {abnormal_text}
    
    Yanıtını şu JSON formatında ver (sadece JSON döndür, ek açıklama ekleme):
    {{
        "health_conditions": [
            {{
                "name": "Hastalık adı",
                "description": "Hastalığın kısa açıklaması",
                "related_values": "İlgili test parametreleri (virgülle ayrılmış)"
            }}
        ]
    }}
    """
    
    # API isteği için gerekli veri
    request_data = {
        "contents": [
            {
                "parts": [
                    {
                        "text": prompt
                    }
                ]
            }
        ],
        "generationConfig": {
            "temperature": 1.0,  # Yaratıcılığı artırmak için temperature değerini yükselttim
            "topP": 0.95,
            "topK": 40,
            "maxOutputTokens": 800
        }
    }
    
    try:
        # API key kontrolü
        if not GEMINI_API_URL or not GEMINI_API_KEY:
            print("[AI Analiz] HATA: Gemini API yapılandırması eksik!")
            print("Lütfen .env dosyasında GEMINI_API_KEY'inizi tanımlayın.")
            return []
        
        # API'ye istek gönder
        print("[AI Analiz] Gemini API'ye istek gönderiliyor...")
        response = requests.post(
            GEMINI_API_URL,
            json=request_data,
            headers={"Content-Type": "application/json"},
            timeout=30
        )
        
        # Yanıtı işle
        if response.status_code == 200:
            print(f"[AI Analiz] API yanıtı başarılı: HTTP {response.status_code}")
            response_data = response.json()
            if 'candidates' in response_data and len(response_data['candidates']) > 0:
                text_response = response_data['candidates'][0]['content']['parts'][0]['text']
                
                # Konsola tam yanıtı yazdir
                print(f"[AI Analiz] Ham API yanıtı:\n{text_response}\n")
                
                # JSON içeriğini ayıkla (bazen API JSON'ı kod bloğu içinde gönderir)
                if "```json" in text_response:
                    json_text = text_response.split("```json")[1].split("```")[0].strip()
                elif "```" in text_response:
                    json_text = text_response.split("```")[1].strip()
                else:
                    json_text = text_response
                
                try:
                    ai_result = json.loads(json_text)
                    print(f"[AI Analiz] İşlenmiş JSON sonucu: {json.dumps(ai_result, indent=2, ensure_ascii=False)}")
                    
                    # AI'dan gelen health_conditions'ı doğrudan döndür, yoksa boş liste
                    health_conditions = ai_result.get('health_conditions', [])
                    if health_conditions:
                        print(f"[AI Analiz] {len(health_conditions)} hastalık tahmini bulundu")
                    else:
                        print("[AI Analiz] Hiç hastalık tahmini bulunamadı")
                        # Varsayılan hastalık listeleri istenmediği için boş liste döndür
                        health_conditions = []
                    return health_conditions
                    
                except json.JSONDecodeError as e:
                    print(f"[AI Analiz] JSON ayrıştırma hatası: {str(e)}")
                    print(f"[AI Analiz] Ayrıştırılamayan JSON metni: {json_text}")
                    # Varsayılan hastalık tahminleri istenmiyor, boş liste döndür
                    return []
        else:
            print(f"[AI Analiz] API hatası: HTTP {response.status_code}")
            print(f"[AI Analiz] Hata detayı: {response.text}")
            
            # 503 hatası için özel mesaj
            if response.status_code == 503:
                print("[AI Analiz] Google Gemini API şu anda meşgul, lütfen birkaç dakika sonra tekrar deneyin.")
            elif response.status_code == 429:
                print("[AI Analiz] API rate limit aşıldı, lütfen bir süre bekleyin.")
            elif response.status_code == 401:
                print("[AI Analiz] API anahtarı geçersiz, lütfen yapılandırmanızı kontrol edin.")
            
            # Varsayılan hastalık tahminleri istenmiyor, boş liste döndür
            return []
    except Exception as e:
        print(f"[AI Analiz] İstek hatası: {str(e)}")
        # Varsayılan hastalık tahminleri istenmiyor, boş liste döndür
        return []

# API endpoint'leri
@app.route('/api/login', methods=['POST'])
def api_login():
    """API üzerinden giriş yapma"""
    data = request.get_json()
    
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({"error": "Eksik bilgi"}), 400
    
    username = data['username']
    password = data['password']
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT id, username, password FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    
    if user and check_password(user[2], password):
        access_token = create_access_token(identity=user[0])
        return jsonify({"access_token": access_token, "user_id": user[0], "username": user[1]}), 200
    
    return jsonify({"error": "Geçersiz kullanıcı adı veya şifre"}), 401

@app.route('/api/analyses', methods=['GET'])
@jwt_required()
def api_get_analyses():
    """Kullanıcının analizlerini getir"""
    user_id = get_jwt_identity()
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM analyses WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    analyses = [dict(row) for row in c.fetchall()]
    conn.close()
    
    return jsonify({"analyses": analyses}), 200

# Admin paneli rotaları
@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin kontrol paneli"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Toplam kullanıcı ve analiz sayılarını getir
    c.execute("SELECT COUNT(*) as user_count FROM users WHERE role != 'admin'")
    user_count = c.fetchone()['user_count']
    
    c.execute("SELECT COUNT(*) as analysis_count FROM analyses")
    analysis_count = c.fetchone()['analysis_count']
    
    # Son 5 kullanıcıyı getir
    c.execute("SELECT * FROM users ORDER BY created_at DESC LIMIT 5")
    recent_users = c.fetchall()
    
    # Son 5 analizi getir
    c.execute("""
        SELECT a.*, u.username 
        FROM analyses a 
        JOIN users u ON a.user_id = u.id 
        ORDER BY a.created_at DESC LIMIT 5
    """)
    recent_analyses = c.fetchall()
    
    # Son 7 günün istatistikleri
    c.execute("""
        SELECT COUNT(*) as count, DATE(created_at) as date
        FROM analyses
        WHERE created_at >= date('now', '-7 days')
        GROUP BY DATE(created_at)
        ORDER BY date
    """)
    daily_stats = c.fetchall()
    
    # En aktif 5 kullanıcı (en çok tahlil yaptıran)
    c.execute("""
        SELECT u.id, u.username, COUNT(a.id) as analysis_count
        FROM users u
        JOIN analyses a ON u.id = a.user_id
        GROUP BY u.id
        ORDER BY analysis_count DESC
        LIMIT 5
    """)
    top_users = c.fetchall()
    
    conn.close()
    
    # Son 7 gün için boş günleri de dolduralım (veri olmayan günler için 0)
    today = datetime.now().date()
    stats_dict = {row['date']: row['count'] for row in daily_stats}
    complete_daily_stats = []
    
    for i in range(7, 0, -1):
        date_str = (today - timedelta(days=i-1)).strftime('%Y-%m-%d')
        complete_daily_stats.append({
            'date': date_str,
            'count': stats_dict.get(date_str, 0)
        })
    
    return render_template('admin/dashboard.html', 
                          user_count=user_count, 
                          analysis_count=analysis_count,
                          recent_users=recent_users,
                          recent_analyses=recent_analyses,
                          daily_stats=complete_daily_stats,
                          top_users=top_users)

@app.route('/admin/users')
@admin_required
def admin_users():
    """Tüm kullanıcıları listele"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = c.fetchall()
    conn.close()
    
    return render_template('admin/users.html', users=users)

@app.route('/admin/users/<int:user_id>')
@admin_required
def admin_user_detail(user_id):
    """Kullanıcı detaylarını görüntüle"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Kullanıcı bilgilerini getir
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        flash('Kullanıcı bulunamadı!', 'danger')
        return redirect(url_for('admin_users'))
    
    # Kullanıcının analizlerini getir
    c.execute("SELECT * FROM analyses WHERE user_id = ? ORDER BY created_at DESC", (user_id,))
    analyses = c.fetchall()
    
    conn.close()
    
    return render_template('admin/user_detail.html', user=user, analyses=analyses)

@app.route('/admin/analyses')
@admin_required
def admin_analyses():
    """Tüm analizleri listele"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("""
        SELECT a.*, u.username 
        FROM analyses a 
        JOIN users u ON a.user_id = u.id 
        ORDER BY a.created_at DESC
    """)
    analyses = c.fetchall()
    
    conn.close()
    
    return render_template('admin/analyses.html', analyses=analyses)

@app.route('/admin/analyses/<int:analysis_id>')
@admin_required
def admin_analysis_detail(analysis_id):
    """Analiz detaylarını görüntüle"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    c.execute("""
        SELECT a.*, u.username 
        FROM analyses a 
        JOIN users u ON a.user_id = u.id 
        WHERE a.id = ?
    """, (analysis_id,))
    analysis = c.fetchone()
    
    conn.close()
    
    if not analysis:
        flash('Analiz bulunamadı!', 'danger')
        return redirect(url_for('admin_analyses'))
        
    return render_template('admin/analysis_detail.html', analysis=analysis)

@app.route('/admin/users/toggle/<int:user_id>', methods=['POST'])
@admin_required
@csrf.exempt
def admin_toggle_user(user_id):
    """Kullanıcı aktiflik durumunu değiştir"""
    # Admin kendisini devre dışı bırakmasın
    if user_id == session['user_id']:
        flash('Kendi hesabınızı devre dışı bırakamazsınız!', 'danger')
        return redirect(url_for('admin_user_detail', user_id=user_id))
        
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Önce mevcut durumu kontrol et
    c.execute("SELECT is_active FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    
    if not user:
        conn.close()
        flash('Kullanıcı bulunamadı!', 'danger')
        return redirect(url_for('admin_users'))
        
    # Durumu tersine çevir
    new_status = 0 if user[0] else 1
    c.execute("UPDATE users SET is_active = ? WHERE id = ?", (new_status, user_id))
    conn.commit()
    conn.close()
    
    status_text = 'aktif' if new_status else 'pasif'
    flash(f'Kullanıcı durumu {status_text} olarak güncellendi!', 'success')
    return redirect(url_for('admin_user_detail', user_id=user_id))

@app.route('/admin/analyses/delete/<int:analysis_id>', methods=['POST'])
@admin_required
@csrf.exempt
def admin_delete_analysis(analysis_id):
    """Analizi sil"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    conn.close()
    
    flash('Analiz başarıyla silindi!', 'success')
    return redirect(url_for('admin_analyses'))

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@admin_required
def admin_delete_user(user_id):
    """Admin işlevi: Bir kullanıcıyı ve tüm analizlerini siler"""
    # Ana admin kullanıcısının silinmesini engelle
    if user_id == 1:
        flash('Ana admin kullanıcısı silinemez!', 'danger')
        return redirect(url_for('admin_users'))
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        # Önce kullanıcıya ait analizleri sil
        c.execute("DELETE FROM analyses WHERE user_id = ?", (user_id,))
        
        # Sonra kullanıcıyı sil
        c.execute("DELETE FROM users WHERE id = ?", (user_id,))
        
        conn.commit()
        flash('Kullanıcı ve tüm analizleri başarıyla silindi!', 'success')
    except Exception as e:
        conn.rollback()
        app.logger.error(f"Kullanıcı silme hatası: {str(e)}")
        flash(f'Kullanıcı silinirken bir hata oluştu: {str(e)}', 'danger')
    finally:
        conn.close()
    
    return redirect(url_for('admin_users'))

@app.route('/admin/newsletter')
@admin_required
def admin_newsletter():
    """Admin newsletter aboneleri sayfası"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Toplam abone sayısı
    c.execute("SELECT COUNT(*) as total FROM newsletter_subscribers WHERE status = 'active'")
    total_subscribers = c.fetchone()['total']
    
    # Bugün abone olan sayısı
    c.execute("SELECT COUNT(*) as today FROM newsletter_subscribers WHERE DATE(created_at) = DATE('now') AND status = 'active'")
    today_subscribers = c.fetchone()['today']
    
    # Son 30 gün abone olan sayısı
    c.execute("SELECT COUNT(*) as month FROM newsletter_subscribers WHERE created_at >= date('now', '-30 days') AND status = 'active'")
    month_subscribers = c.fetchone()['month']
    
    # Son aboneler
    c.execute("SELECT * FROM newsletter_subscribers ORDER BY created_at DESC LIMIT 50")
    subscribers = c.fetchall()
    
    # Günlük abone istatistikleri (son 7 gün)
    c.execute("""
        SELECT COUNT(*) as count, DATE(created_at) as date
        FROM newsletter_subscribers
        WHERE created_at >= date('now', '-7 days') AND status = 'active'
        GROUP BY DATE(created_at)
        ORDER BY date
    """)
    daily_stats = c.fetchall()
    
    conn.close()
    
    return render_template('admin/newsletter.html',
                         total_subscribers=total_subscribers,
                         today_subscribers=today_subscribers,
                         month_subscribers=month_subscribers,
                         subscribers=subscribers,
                         daily_stats=daily_stats)

@app.route('/admin/newsletter/export')
@admin_required
def admin_newsletter_export():
    """Newsletter abonelerini CSV olarak dışa aktar"""
    import csv
    from io import StringIO
    from flask import make_response
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT email, status, created_at FROM newsletter_subscribers ORDER BY created_at DESC")
    subscribers = c.fetchall()
    conn.close()
    
    # CSV oluştur
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Email', 'Durum', 'Kayıt Tarihi'])
    
    for subscriber in subscribers:
        writer.writerow([subscriber['email'], subscriber['status'], subscriber['created_at']])
    
    # Response oluştur
    response = make_response(output.getvalue())
    response.headers['Content-Type'] = 'text/csv'
    response.headers['Content-Disposition'] = 'attachment; filename=newsletter_aboneleri.csv'
    
    return response

# Abonelik işlemleri
@app.route('/subscription/plans')
def subscription_plans():
    """Abonelik planlarını görüntüle"""
    if 'user_id' not in session:
        flash('Abonelik planlarını görüntülemek için giriş yapmalısınız!', 'warning')
        return redirect(url_for('login'))
    
    # Kullanıcının aktif planını getir
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT subscription_plan FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    user_plan = user['subscription_plan'] if user else 'free'
    conn.close()
    
    return render_template('subscription/plans.html', plans=SUBSCRIPTION_PLANS, user_plan=user_plan)







@app.route('/subscription/cancel')
def subscription_cancel():
    """Aboneliği iptal et"""
    if 'user_id' not in session:
        flash('Aboneliğinizi iptal etmek için giriş yapmalısınız!', 'warning')
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Mevcut aboneliği güncelle
    c.execute("""
        UPDATE subscriptions 
        SET status = 'canceled' 
        WHERE user_id = ? AND status = 'active'
    """, (session['user_id'],))
    
    # Kullanıcıyı ücretsiz plana geçir
    c.execute("""
        UPDATE users 
        SET subscription_plan = 'free', subscription_status = 'canceled' 
        WHERE id = ?
    """, (session['user_id'],))
    
    conn.commit()
    conn.close()
    
    flash('Aboneliğiniz iptal edildi. Bu dönem sonuna kadar özelliklerden yararlanmaya devam edebilirsiniz.', 'success')
    return redirect(url_for('subscription_plans'))

# Yeni Ödeme Sistemi Route'ları (Yeni ödeme sistemi buraya eklenecek)







def activate_subscription(user_id, plan_id, payment_provider, transaction_id, amount):
    """Aboneliği aktifleştirir (Stripe ve diğer ödeme sistemleri için ortak)"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Abonelik bitiş tarihini belirle (1 ay sonrası)
        end_date = datetime.now() + timedelta(days=30)
        
        # Kullanıcıyı güncelle
        c.execute("""
            UPDATE users 
            SET subscription_plan = ?, 
                subscription_end_date = ?, 
                last_payment_date = CURRENT_TIMESTAMP,
                payment_provider = ?,
                transaction_id = ?
            WHERE id = ?
        """, (plan_id, end_date.isoformat(), payment_provider, transaction_id, user_id))
        
        # Ödeme geçmişine ekle
        c.execute("""
            INSERT INTO payment_history (user_id, plan_id, amount, payment_provider, transaction_id, status)
            VALUES (?, ?, ?, ?, ?, 'completed')
        """, (user_id, plan_id, amount, payment_provider, transaction_id))
        
        conn.commit()
        conn.close()
        
        app.logger.info(f"Abonelik aktifleştirildi: User {user_id}, Plan {plan_id}, Provider {payment_provider}")
        
    except Exception as e:
        app.logger.error(f"Abonelik aktivasyon hatası: {str(e)}")

@app.route('/about')
def about():
    """Hakkımızda sayfasını görüntüle"""
    return render_template('about.html')

@app.route('/kvkk')
def kvkk():
    """KVKK Aydınlatma Metni sayfasını görüntüle"""
    return render_template('kvkk.html')

@app.route('/gizlilik')
def gizlilik():
    """Gizlilik Politikası sayfasını görüntüle"""
    return render_template('gizlilik.html')

@app.route('/kullanim_kosullari')
def kullanim_kosullari():
    """Kullanım Koşulları sayfasını görüntüle"""
    return render_template('kullanim_kosullari.html')

@app.route('/cerez_politikasi')
def cerez_politikasi():
    """Çerez Politikası sayfasını görüntüle"""
    return render_template('cerez_politikasi.html')

# Blog routes
@app.route('/blog')
def blog():
    """Sağlık Rehberi Blog Ana Sayfası"""
    # URL parametrelerini al
    kategori = request.args.get('kategori', '')
    arama = request.args.get('q', '')
    sayfa = int(request.args.get('sayfa', 1))
    
    # Blog makalelerini hazırla (Gelecekte veritabanından gelecek)
    blog_makaleleri = get_blog_articles()
    
    # Filtreleme
    filtered_articles = blog_makaleleri
    if kategori:
        filtered_articles = [makale for makale in filtered_articles if makale['kategori'] == kategori]
    if arama:
        filtered_articles = [makale for makale in filtered_articles if 
                           arama.lower() in makale['baslik'].lower() or 
                           arama.lower() in makale['ozet'].lower()]
    
    # Sayfalama
    per_page = 9
    total = len(filtered_articles)
    start = (sayfa - 1) * per_page
    end = start + per_page
    articles = filtered_articles[start:end]
    
    # Sayfa bilgileri
    has_next = end < total
    has_prev = sayfa > 1
    next_page = sayfa + 1 if has_next else None
    prev_page = sayfa - 1 if has_prev else None
    
    # Kategoriler
    kategoriler = ['Kan Tahlilleri', 'Beslenme', 'Kalp Sağlığı', 'Diyabet', 'Kolesterol', 'Hormonlar', 'Vitaminler', 'Genel Sağlık']
    
    return render_template('blog/index.html', 
                         articles=articles,
                         kategoriler=kategoriler,
                         secili_kategori=kategori,
                         arama=arama,
                         sayfa=sayfa,
                         has_next=has_next,
                         has_prev=has_prev,
                         next_page=next_page,
                         prev_page=prev_page,
                         total=total)

@app.route('/blog/<slug>')
def blog_makale(slug):
    """Blog makale detay sayfası"""
    # Makaleyi slug ile bul
    blog_makaleleri = get_blog_articles()
    makale = next((m for m in blog_makaleleri if m['slug'] == slug), None)
    
    if not makale:
        return render_template('error.html', error_message='Makale bulunamadı.'), 404
    
    # İlgili makaleler
    ilgili_makaleler = [m for m in blog_makaleleri 
                       if m['kategori'] == makale['kategori'] and m['slug'] != slug][:3]
    
    return render_template('blog/makale.html', 
                         makale=makale, 
                         ilgili_makaleler=ilgili_makaleler)

# Newsletter endpoints
@app.route('/newsletter/subscribe', methods=['POST'])
@csrf.exempt
def newsletter_subscribe():
    """Newsletter abone olma endpoint'i"""
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'success': False, 'message': 'E-posta adresi gerekli.'}), 400
        
        email = data['email'].strip().lower()
        
        # Email doğrulama
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return jsonify({'success': False, 'message': 'Geçerli bir e-posta adresi girin.'}), 400
        
        # Veritabanına kaydet
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        try:
            c.execute("INSERT INTO newsletter_subscribers (email) VALUES (?)", (email,))
            conn.commit()
            
            # Başarılı yanıt
            response_data = {
                'success': True, 
                'message': 'Başarıyla abone oldunuz! Sağlık güncellemeleri e-posta kutunuza gelecek.'
            }
            
            # Hoş geldin email'i gönder
            try:
                html_content, plain_content = get_welcome_email_template(email)
                send_email_async(
                    to_email=email,
                    subject="🎉 MedikalAI Sağlık Rehberi'ne Hoş Geldiniz!",
                    html_content=html_content,
                    plain_content=plain_content
                )
                app.logger.info(f"Hoş geldin emaili gönderildi: {email}")
            except Exception as email_error:
                app.logger.error(f"Email gönderme hatası: {str(email_error)}")
                # Email hatası olsa bile abonelik başarılı, sadece log'a kaydet
            
            return jsonify(response_data), 200
            
        except sqlite3.IntegrityError:
            # E-posta zaten kayıtlı
            return jsonify({
                'success': False, 
                'message': 'Bu e-posta adresi zaten abone listesinde.'
            }), 409
            
        except Exception as db_error:
            app.logger.error(f"Newsletter veritabanı hatası: {str(db_error)}")
            return jsonify({
                'success': False, 
                'message': 'Abonelik işlemi sırasında bir hata oluştu. Lütfen tekrar deneyin.'
            }), 500
            
        finally:
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Newsletter abone olma hatası: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'Beklenmeyen bir hata oluştu. Lütfen tekrar deneyin.'
        }), 500

@app.route('/newsletter/unsubscribe', methods=['POST'])
@csrf.exempt
def newsletter_unsubscribe():
    """Newsletter abonelikten çıkma endpoint'i"""
    try:
        data = request.get_json()
        if not data or 'email' not in data:
            return jsonify({'success': False, 'message': 'E-posta adresi gerekli.'}), 400
        
        email = data['email'].strip().lower()
        
        # Veritabanından çıkar
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute("UPDATE newsletter_subscribers SET status = 'unsubscribed' WHERE email = ?", (email,))
        
        if c.rowcount > 0:
            conn.commit()
            return jsonify({
                'success': True, 
                'message': 'Aboneliğiniz başarıyla iptal edildi.'
            }), 200
        else:
            return jsonify({
                'success': False, 
                'message': 'Bu e-posta adresi abone listesinde bulunamadı.'
            }), 404
            
    except Exception as e:
        app.logger.error(f"Newsletter abonelik iptali hatası: {str(e)}")
        return jsonify({
            'success': False, 
            'message': 'Abonelik iptali sırasında bir hata oluştu.'
        }), 500
    finally:
        if 'conn' in locals():
            conn.close()

def get_blog_articles():
    """Blog makalelerini döndürür (SEO optimize edilmiş içerikler)"""
    return [
        {
            'id': 1,
            'baslik': 'Hemogram Testi Nedir? Sonuçları Nasıl Yorumlanır?',
            'slug': 'hemogram-testi-nedir-sonuclari-nasil-yorumlanir',
            'ozet': 'Hemogram testi kan sağlığınız hakkında önemli bilgiler verir. Değerlerinizi doğru yorumlayın.',
            'kategori': 'Kan Tahlilleri',
            'yazar': 'Dr. Mehmet Özkan',
            'tarih': '2024-01-15',
            'okuma_suresi': '8 dakika',
            'gorsel': '/static/assets/hemogram-test.jpg',
            'etiketler': ['hemogram', 'kan tahlili', 'akyuvar', 'alyuvar', 'trombosit'],
            'meta_description': 'Hemogram testi sonuçlarınızı anlamak için rehber. Akyuvar, alyuvar, trombosit değerleri ve normal aralıklar.',
            'icerik': '''
            <h2>Hemogram Testi Nedir?</h2>
            <p>Hemogram, kan hücrelerinizin sayısını ve özelliklerini ölçen temel kan testidir. Bu test anemiden enfeksiyona, kanama bozukluklarından kan kanserine kadar birçok durumu tespit edebilir.</p>
            
            <h3>Hemogram Testinde Ölçülen Değerler</h3>
            <ul>
                <li><strong>Alyuvar (RBC):</strong> Oksijen taşıyan kan hücreleri</li>
                <li><strong>Hemoglobin (HGB):</strong> Oksijen bağlayan protein</li>
                <li><strong>Hematokrit (HCT):</strong> Kandaki alyuvar oranı</li>
                <li><strong>Akyuvar (WBC):</strong> Enfeksiyonla savaşan kan hücreleri</li>
                <li><strong>Trombosit (PLT):</strong> Kan pıhtılaşmasını sağlayan hücreler</li>
            </ul>
            
            <h3>Normal Değer Aralıkları</h3>
            <table class="table table-striped">
                <tr><td>Hemoglobin (Erkek)</td><td>14-18 g/dL</td></tr>
                <tr><td>Hemoglobin (Kadın)</td><td>12-16 g/dL</td></tr>
                <tr><td>Akyuvar</td><td>4.500-11.000 /μL</td></tr>
                <tr><td>Trombosit</td><td>150.000-450.000 /μL</td></tr>
            </table>
            
            <h3>Anormal Sonuçlar Ne Anlama Gelir?</h3>
            <p>Hemogram sonuçlarınızda anormallik görüldüğünde panik yapmayın. Birçok faktör bu değerleri etkileyebilir.</p>
            '''
        },
        {
            'id': 2,
            'baslik': 'Kolesterol Düzeyleri: LDL, HDL ve Total Kolesterol Rehberi',
            'slug': 'kolesterol-duzeyleri-ldl-hdl-total-kolesterol-rehberi',
            'ozet': 'Kolesterol değerlerinizi anlamak kalp sağlığınız için kritik. İyi ve kötü kolesterol arasındaki farkı öğrenin.',
            'kategori': 'Kolesterol',
            'yazar': 'Dr. Ayşe Demir',
            'tarih': '2024-01-10',
            'okuma_suresi': '6 dakika',
            'gorsel': '/static/assets/kolesterol-test.jpg',
            'etiketler': ['kolesterol', 'ldl', 'hdl', 'kalp sağlığı', 'trigliserit'],
            'meta_description': 'Kolesterol testi sonuçları rehberi. LDL, HDL, total kolesterol normal değerleri ve yüksek kolesterolü düşürme yolları.',
            'icerik': '''
            <h2>Kolesterol Nedir?</h2>
            <p>Kolesterol, vücudunuzun hücre duvarları ve hormon üretimi için ihtiyaç duyduğu mumsu bir maddedir. Ancak fazlası kalp hastalığı riskini artırır.</p>
            
            <h3>Kolesterol Türleri</h3>
            <h4>LDL Kolesterol (Kötü Kolesterol)</h4>
            <p>Düşük yoğunluklu lipoprotein (LDL), arterlerde plak birikimine neden olabilir.</p>
            <ul>
                <li>İdeal: 100 mg/dL altı</li>
                <li>Sınırda yüksek: 130-159 mg/dL</li>
                <li>Yüksek: 160 mg/dL üzeri</li>
            </ul>
            
            <h4>HDL Kolesterol (İyi Kolesterol)</h4>
            <p>Yüksek yoğunluklu lipoprotein (HDL), arterlerden kolesterolü temizler.</p>
            <ul>
                <li>Erkekler için ideal: 40 mg/dL üzeri</li>
                <li>Kadınlar için ideal: 50 mg/dL üzeri</li>
                <li>Mükemmel: 60 mg/dL üzeri</li>
            </ul>
            '''
        },
        {
            'id': 3,
            'baslik': 'Diyabet Tanısında Kullanılan Testler: HbA1c ve Açlık Şekeri',
            'slug': 'diyabet-tanisinda-kullanilan-testler-hba1c-aclik-sekeri',
            'ozet': 'Diyabet tanısı için hangi testler yapılır? HbA1c ve açlık şekeri testlerini anlayın.',
            'kategori': 'Diyabet',
            'yazar': 'Dr. Mehmet Özkan',
            'tarih': '2024-01-05',
            'okuma_suresi': '7 dakika',
            'gorsel': '/static/assets/diyabet-test.jpg',
            'etiketler': ['diyabet', 'hba1c', 'açlık şekeri', 'glukoz', 'insülin'],
            'meta_description': 'Diyabet testleri rehberi. HbA1c, açlık şekeri ve glukoz tolerans testi normal değerleri ve yorumları.',
            'icerik': '''
            <h2>Diyabet Tanı Testleri</h2>
            <p>Diyabet tanısı için kullanılan temel testler kan şekeri seviyenizi farklı açılardan değerlendirir.</p>
            
            <h3>HbA1c Testi</h3>
            <p>Son 2-3 ayın ortalama kan şekeri seviyesini gösterir.</p>
            <ul>
                <li>Normal: %5.7 altı</li>
                <li>Prediyabet: %5.7-6.4</li>
                <li>Diyabet: %6.5 üzeri</li>
            </ul>
            
            <h3>Açlık Kan Şekeri</h3>
            <p>8-12 saat açlık sonrası ölçülen kan şekeri değeri.</p>
            <ul>
                <li>Normal: 70-99 mg/dL</li>
                <li>Prediyabet: 100-125 mg/dL</li>
                <li>Diyabet: 126 mg/dL üzeri</li>
            </ul>
            '''
        },
        {
            'id': 4,
            'baslik': 'Tiroid Fonksiyon Testleri: TSH, T3, T4 Değerleri',
            'slug': 'tiroid-fonksiyon-testleri-tsh-t3-t4-degerleri',
            'ozet': 'Tiroid bezinizin sağlığını TSH, T3, T4 testleriyle kontrol edin. Normal değerler ve anlamları.',
            'kategori': 'Hormonlar',
            'yazar': 'Dr. Fatma Yılmaz',
            'tarih': '2024-01-12',
            'okuma_suresi': '9 dakika',
            'gorsel': '/static/assets/tiroid-test.jpg',
            'etiketler': ['tiroid', 'tsh', 't3', 't4', 'hipotiroid', 'hipertiroid'],
            'meta_description': 'Tiroid testleri rehberi. TSH, T3, T4 normal değerleri, hipotiroid ve hipertiroid belirtileri.',
            'icerik': '''
            <h2>Tiroid Fonksiyon Testleri</h2>
            <p>Tiroid bezi metabolizmanızı kontrol eden önemli hormonlar üretir. Bu testler tiroid sağlığınızı değerlendirir.</p>
            
            <h3>TSH (Tiroid Stimülan Hormon)</h3>
            <p>Hipofiz bezinden salgılanan ve tiroid bezini uyaran hormon.</p>
            <ul>
                <li>Normal aralık: 0.5-4.5 mIU/L</li>
                <li>Yüksek TSH: Hipotiroid</li>
                <li>Düşük TSH: Hipertiroid</li>
            </ul>
            '''
        },
        {
            'id': 5,
            'baslik': 'Vitamin D Eksikliği: Belirtiler ve Test Sonuçları',
            'slug': 'vitamin-d-eksikligi-belirtiler-test-sonuclari',
            'ozet': 'Vitamin D eksikliği yaygın bir sağlık sorunu. Test sonuçlarınızı anlayın ve eksikliği giderin.',
            'kategori': 'Vitaminler',
            'yazar': 'Dr. Can Öztürk',
            'tarih': '2024-01-08',
            'okuma_suresi': '5 dakika',
            'gorsel': '/static/assets/vitamin-d-test.jpg',
            'etiketler': ['vitamin d', 'kemik sağlığı', 'güneş vitamini', 'eksiklik'],
            'meta_description': 'Vitamin D testi sonuçları ve eksiklik belirtileri. Normal vitamin D düzeyleri ve takviye önerileri.',
            'icerik': '''
            <h2>Vitamin D ve Önemi</h2>
            <p>Vitamin D kemik sağlığı, bağışıklık sistemi ve birçok vücut fonksiyonu için kritiktir.</p>
            
            <h3>Vitamin D Seviyeleri</h3>
            <ul>
                <li>Eksiklik: 20 ng/mL altı</li>
                <li>Yetersizlik: 20-30 ng/mL</li>
                <li>Yeterli: 30-100 ng/mL</li>
                <li>Fazla: 100 ng/mL üzeri</li>
            </ul>
            '''
        },
        {
            'id': 6,
            'baslik': 'Karaciğer Fonksiyon Testleri: ALT, AST, Bilirubin',
            'slug': 'karaciger-fonksiyon-testleri-alt-ast-bilirubin',
            'ozet': 'Karaciğer sağlığınızı ALT, AST ve bilirubin testleriyle kontrol edin. Normal değerler ve anlamları.',
            'kategori': 'Kan Tahlilleri',
            'yazar': 'Dr. Ahmet Kaya',
            'tarih': '2024-01-14',
            'okuma_suresi': '6 dakika',
            'gorsel': '/static/assets/karaciger-test.jpg',
            'etiketler': ['karaciğer', 'alt', 'ast', 'bilirubin', 'hepatit'],
            'meta_description': 'Karaciğer fonksiyon testleri rehberi. ALT, AST, bilirubin normal değerleri ve karaciğer hastalıkları.',
            'icerik': '''
            <h2>Karaciğer Fonksiyon Testleri</h2>
            <p>Karaciğer testleri organ hasarını veya hastalığını erken tespit etmeye yardımcı olur.</p>
            
            <h3>ALT (Alanin Aminotransferaz)</h3>
            <p>Karaciğer hasarının en hassas göstergesi.</p>
            <ul>
                <li>Erkekler: 10-40 U/L</li>
                <li>Kadınlar: 7-35 U/L</li>
            </ul>
            '''
        },
        {
            'id': 7,
            'baslik': 'Böbrek Fonksiyon Testleri: Kreatinin ve Üre Değerleri',
            'slug': 'bobrek-fonksiyon-testleri-kreatinin-ure-degerleri',
            'ozet': 'Böbrek sağlığınızı kreatinin ve üre testleriyle takip edin. Normal değerler ve böbrek hastalığı belirtileri.',
            'kategori': 'Kan Tahlilleri',
            'yazar': 'Dr. Zeynep Aktaş',
            'tarih': '2024-01-09',
            'okuma_suresi': '7 dakika',
            'gorsel': '/static/assets/bobrek-test.jpg',
            'etiketler': ['böbrek', 'kreatinin', 'üre', 'gfr', 'böbrek yetmezliği'],
            'meta_description': 'Böbrek fonksiyon testleri rehberi. Kreatinin, üre, GFR normal değerleri ve böbrek hastalığı tanısı.',
            'icerik': '''
            <h2>Böbrek Fonksiyon Testleri</h2>
            <p>Böbrek testleri organ fonksiyonunu değerlendirmek ve hastalığı erken tespit etmek için kullanılır.</p>
            
            <h3>Kreatinin</h3>
            <p>Böbrek fonksiyonunun en önemli göstergesi.</p>
            <ul>
                <li>Erkekler: 0.7-1.2 mg/dL</li>
                <li>Kadınlar: 0.6-1.1 mg/dL</li>
            </ul>
            '''
        },
        {
            'id': 8,
            'baslik': 'Kalp Sağlığı İçin Önemli Testler: Troponin ve CK-MB',
            'slug': 'kalp-sagligi-icin-onemli-testler-troponin-ck-mb',
            'ozet': 'Kalp krizi tanısında kullanılan troponin ve CK-MB testlerini öğrenin. Kalp sağlığınızı koruyun.',
            'kategori': 'Kalp Sağlığı',
            'yazar': 'Dr. Murat Özdemir',
            'tarih': '2024-01-11',
            'okuma_suresi': '8 dakika',
            'gorsel': '/static/assets/kalp-test.jpg',
            'etiketler': ['kalp', 'troponin', 'ck-mb', 'miyokard infarktüsü', 'kalp krizi'],
            'meta_description': 'Kalp sağlığı testleri rehberi. Troponin, CK-MB değerleri ve kalp krizi tanısında kullanımları.',
            'icerik': '''
            <h2>Kalp Sağlığı Testleri</h2>
            <p>Kalp hasarını tespit etmek için kullanılan özel enzim ve protein testleri.</p>
            
            <h3>Troponin</h3>
            <p>Kalp krizi tanısında altın standart test.</p>
            <ul>
                <li>Normal: 0.04 ng/mL altı</li>
                <li>Yüksek değerler kalp hasarını gösterir</li>
            </ul>
            '''
        }
    ]

# CSRF hata yönetimi
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    """CSRF hatası durumunda kullanıcıya bilgi ver"""
    return render_template('error.html', message="CSRF doğrulama hatası. Lütfen sayfayı yenileyip tekrar deneyin."), 400

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Sayfa bulunamadı"), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error_code=500, error_message="Sunucu hatası"), 500

if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 8080)), debug=False)
