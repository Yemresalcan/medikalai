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
import stripe

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10 MB limit
app.secret_key = secrets.token_hex(16)  # Güvenli rastgele anahtar

# Stripe yapılandırması
STRIPE_API_KEY = "sk_test_51XXXXXXXXXXXXXXXXXXXXXX"  # Test API anahtarı - gerçek anahtarla değiştirin
STRIPE_PUBLIC_KEY = "pk_test_51XXXXXXXXXXXXXXXXXXXXXX"  # Test Public API anahtarı
stripe.api_key = STRIPE_API_KEY
app.config['STRIPE_PUBLIC_KEY'] = STRIPE_PUBLIC_KEY

# CSRF koruması
csrf = CSRFProtect(app)

# JWT konfigurasyonu
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)  # JWT için farklı bir güvenli anahtar
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token geçerlilik süresi
jwt = JWTManager(app)

# Gemini API anahtarı ve endpoint
GEMINI_API_KEY = "AIzaSyBQLZ2W8mHu3IOoTl1pxdeetUC_bzu-j58"  # Gerçek API anahtarınızla değiştirin
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"

# Veritabanı ayarları
DB_PATH = os.environ.get('DB_PATH', 'kan_tahlil_app.db')

# Abonelik planları
SUBSCRIPTION_PLANS = {
    'free': {
        'name': 'Ücretsiz',
        'price': 0,
        'description': 'Aylık 3 tahlil analizi',
        'analysis_limit': 3,
        'stripe_price_id': None,
        'features': ['Temel analiz', 'Sınırlı tahlil sayısı', 'Tahlil geçmişi']
    },
    'basic': {
        'name': 'Temel',
        'price': 49.90,
        'description': 'Aylık 10 tahlil analizi',
        'analysis_limit': 10,
        'stripe_price_id': 'price_1XxXxXxXxXxXxXxXxXxXxXx',
        'features': ['Detaylı analiz', '10 tahlil/ay', 'Tahlil geçmişi', 'PDF rapor indirme']
    },
    'premium': {
        'name': 'Premium',
        'price': 89.90,
        'description': 'Sınırsız tahlil analizi',
        'analysis_limit': float('inf'),
        'stripe_price_id': 'price_1YyYyYyYyYyYyYyYyYyYyYy',
        'features': ['Kapsamlı analiz', 'Sınırsız tahlil', 'Tahlil geçmişi', 'PDF rapor indirme', 'E-posta bildirim', 'Öncelikli destek']
    },
    'family': {
        'name': 'Aile',
        'price': 129.90,
        'description': '5 aile üyesi için sınırsız tahlil analizi',
        'analysis_limit': float('inf'),
        'stripe_price_id': 'price_1ZzZzZzZzZzZzZzZzZzZzZz',
        'features': ['Kapsamlı analiz', 'Sınırsız tahlil', '5 aile üyesi', 'Tahlil geçmişi', 'PDF rapor indirme', 'E-posta bildirim', 'Öncelikli destek']
    }
}

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
        c.execute("SELECT subscription_plan FROM users WHERE id = ?", (session['user_id'],))
        user = c.fetchone()
        current_plan = user['subscription_plan'] if user else 'free'
        
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
            if remaining_analyses <= 0 and current_plan not in ['premium', 'family']:
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
            
            # Prompt'u yapılandırılmış veri alacak şekilde iyileştiriyoruz
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
            
            try:
                # Gemini API isteği
                headers = {
                    "Content-Type": "application/json",
                    "X-Requested-With": "XMLHttpRequest"  # API'ye AJAX isteği olduğunu bildir
                }
                
                # API isteği gönderiliyor
                print(f"Gemini API'ye istek gönderiliyor: {GEMINI_API_URL}")    
                response = requests.post(
                    GEMINI_API_URL,
                    headers=headers,
                    json=data,
                    timeout=30  # Zaman aşımını 30 saniyeye ayarlıyoruz
                )
                
                # HTTP hatası kontrol et
                if response.status_code != 200:
                    print(f"API Hata Kodu: {response.status_code}")
                    print(f"API Yanıtı: {response.text[:500]}")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({"error": f"API hatası: HTTP {response.status_code}"}), 500
                    flash(f'API hatası: HTTP {response.status_code}', 'danger')
                    return redirect(url_for('analyze'))
                
                # Yanıtı işle
                response_data = response.json()
                
                if "candidates" in response_data and response_data["candidates"]:
                    result_text = response_data["candidates"][0]["content"]["parts"][0]["text"]
                    
                    # Yanıt boş mu kontrol et
                    if not result_text or not result_text.strip():
                        print("API yanıtı boş")
                        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                            return jsonify({"error": "API yanıtı boş. Lütfen tekrar deneyin."}), 500
                        flash('API yanıtı boş. Lütfen tekrar deneyin.', 'danger')
                        return redirect(url_for('analyze'))
                    
                    # Metni paragraf ve bölümlere ayır
                    # Başlıklar ve alt başlıkları bulmak için
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
                    normal_values = []
                    
                    if "ANORMAL DEĞERLERİ" in sections or "NORMAL DIŞI DEĞERLER" in sections:
                        abnormal_section = sections.get("ANORMAL DEĞERLERİ", sections.get("NORMAL DIŞI DEĞERLER", ""))
                        for line in abnormal_section.split('\n'):
                            if ":" in line:
                                param_name = line.split(":")[0].strip()
                                abnormal_values.append({"parameter_name": param_name, "description": line})
                    
                    try:
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
                        
                        # Bölümleri JSON olarak kaydet (şablon uyumluluğu için)
                        analysis_json = {
                            "summary": sections.get("Genel Değerlendirme", ""),
                            "abnormal_count": len(abnormal_values),
                            "test_groups": [],
                            "recommendations": sections.get("ÖNERİLER", "").split('\n') if "ÖNERİLER" in sections else [],
                            "lifestyle_advice": sections.get("YAŞAM TARZI ÖNERİLERİ", "").split('\n') if "YAŞAM TARZI ÖNERİLERİ" in sections else [],
                            "health_conditions": [],
                            "general_analysis": result_text
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
                else:
                    print(f"API yanıtı candidates içermiyor: {response_data}")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({"error": "API yanıtı beklenen formatta değil."}), 500
                    flash('API yanıtı beklenen formatta değil.', 'danger')
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
    
    conn.close()
    
    # Şablona bilgileri aktar
    return render_template('result.html', 
                          analysis=analysis,
                          abnormal_values=abnormal_values,
                          analysis_json=analysis_json,
                          test_values=[])  # Test değerlerini şu an boş liste olarak gönder

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
        # API'ye istek gönder
        print("[AI Analiz] Gemini API'ye istek gönderiliyor...")
        response = requests.post(
            GEMINI_API_URL,
            json=request_data,
            headers={"Content-Type": "application/json"}
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

@app.route('/subscription/checkout/<plan_id>')
def subscription_checkout(plan_id):
    """Ödeme sayfasını görüntüle"""
    if 'user_id' not in session:
        flash('Abonelik satın almak için giriş yapmalısınız!', 'warning')
        return redirect(url_for('login'))
    
    if plan_id not in SUBSCRIPTION_PLANS:
        flash('Geçersiz abonelik planı!', 'danger')
        return redirect(url_for('subscription_plans'))
    
    # Ücretsiz plan için ödeme sayfası gösterme
    if plan_id == 'free':
        return redirect(url_for('subscription_plans'))
    
    # Kullanıcının mevcut planı seçili plandan daha yüksekse uyarı göster
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT subscription_plan FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    current_plan = user['subscription_plan'] if user else 'free'
    conn.close()
    
    # Planların değerini karşılaştır
    # Eğer kullanıcı zaten daha yüksek bir plana sahipse ve daha düşük bir plana geçmek istiyorsa uyarı göster
    current_plan_value = SUBSCRIPTION_PLANS[current_plan]['price']
    new_plan_value = SUBSCRIPTION_PLANS[plan_id]['price']
    
    if current_plan != 'free' and new_plan_value < current_plan_value:
        flash("""
            Daha düşük bir plana geçmek istediğinizi fark ettik. 
            Mevcut planınızın süresi dolana kadar mevcut özellikleri kullanmaya devam edeceksiniz. 
            Yeni plan sonraki ödeme döneminde aktif olacaktır.
        """, 'warning')
    
    # Seçilen planı ve ödeme bilgilerini görüntüle
    plan = SUBSCRIPTION_PLANS[plan_id]
    
    return render_template(
        'subscription/checkout.html', 
        plan=plan, 
        plan_id=plan_id, 
        stripe_public_key=app.config['STRIPE_PUBLIC_KEY']
    )

@app.route('/subscription/create_payment_intent/<plan_id>', methods=['POST'])
def create_payment_intent(plan_id):
    """Stripe ödeme niyeti oluştur"""
    if 'user_id' not in session:
        return jsonify({'error': 'Oturum süresi doldu, lütfen tekrar giriş yapın.'}), 401
    
    if plan_id not in SUBSCRIPTION_PLANS:
        return jsonify({'error': 'Geçersiz abonelik planı!'}), 400
    
    plan = SUBSCRIPTION_PLANS[plan_id]
    
    # Kullanıcı bilgilerini getir
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT email, stripe_customer_id FROM users WHERE id = ?", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    
    try:
        # Stripe müşteri ID'si yoksa yeni müşteri oluştur
        customer_id = user['stripe_customer_id']
        if not customer_id:
            customer = stripe.Customer.create(
                email=user['email'],
                description=f"Kullanıcı ID: {session['user_id']}"
            )
            customer_id = customer.id
            
            # Kullanıcı tablosunda Stripe müşteri ID'sini güncelle
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute("UPDATE users SET stripe_customer_id = ? WHERE id = ?", 
                     (customer_id, session['user_id']))
            conn.commit()
            conn.close()
        
        # Kuruş cinsinden fiyat hesapla (KDV dahil)
        amount = int(plan['price'] * 118)  # %18 KDV ekle ve kuruş cinsine çevir
        
        # Ödeme niyeti oluştur
        intent = stripe.PaymentIntent.create(
            amount=amount,
            currency='try',
            customer=customer_id,
            metadata={
                'user_id': session['user_id'],
                'plan_id': plan_id,
                'plan_name': plan['name']
            },
            description=f"{plan['name']} Abonelik Planı"
        )
        
        return jsonify({
            'clientSecret': intent.client_secret
        })
    except Exception as e:
        app.logger.error(f"Stripe ödeme hatası: {str(e)}")
        return jsonify({'error': 'Ödeme işlemi sırasında bir hata oluştu. Lütfen daha sonra tekrar deneyin.'}), 500

@app.route('/subscription/success/<plan_id>')
def subscription_success(plan_id):
    """Ödeme başarılı sayfası"""
    if 'user_id' not in session:
        flash('Oturum süresi doldu, lütfen tekrar giriş yapın.', 'warning')
        return redirect(url_for('login'))
    
    if plan_id not in SUBSCRIPTION_PLANS:
        flash('Geçersiz abonelik planı!', 'danger')
        return redirect(url_for('subscription_plans'))
    
    plan = SUBSCRIPTION_PLANS[plan_id]
    
    # Kullanıcının abonelik planını güncelle
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Abonelik bitiş tarihini belirle (1 ay sonrası)
    end_date = datetime.now() + timedelta(days=30)
    
    # Kullanıcıyı güncelle
    c.execute("""
        UPDATE users 
        SET subscription_plan = ?, subscription_status = 'active', subscription_end_date = ? 
        WHERE id = ?
    """, (plan_id, end_date, session['user_id']))
    
    # Örnek işlem kaydı oluştur
    transaction = {
        'id': f"TRANS-{secrets.token_hex(6).upper()}",
        'date': datetime.now().strftime('%d.%m.%Y %H:%M'),
        'start_date': datetime.now().strftime('%d.%m.%Y'),
        'end_date': end_date.strftime('%d.%m.%Y'),
        'last4': '4242'  # Gerçek Stripe entegrasyonunda bu değer kart bilgisinden gelir
    }
    
    # Abonelik kaydı oluştur
    c.execute("""
        INSERT INTO subscriptions 
        (user_id, plan_type, status, current_period_start, current_period_end) 
        VALUES (?, ?, 'active', ?, ?)
    """, (session['user_id'], plan_id, datetime.now(), end_date))
    
    subscription_id = c.lastrowid
    
    # Fatura kaydı oluştur
    c.execute("""
        INSERT INTO invoices 
        (user_id, subscription_id, amount, currency, status, invoice_date) 
        VALUES (?, ?, ?, 'TRY', 'paid', ?)
    """, (session['user_id'], subscription_id, plan['price'] * 1.18, datetime.now()))
    
    conn.commit()
    conn.close()
    
    flash(f'{plan["name"]} aboneliğiniz başarıyla oluşturuldu!', 'success')
    
    return render_template('subscription/success.html', plan=plan, transaction=transaction)

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
