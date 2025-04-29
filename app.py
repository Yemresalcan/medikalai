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

# Session ayarlarını düzenle
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_TYPE'] = 'filesystem'

# Vercel için session yapılandırması
if os.environ.get('VERCEL_ENV'):
    # Vercel'de session cookie ayarları
    app.config['SESSION_COOKIE_SECURE'] = True
    app.config['SESSION_COOKIE_PATH'] = '/'
    app.config['SESSION_COOKIE_DOMAIN'] = None

# Stripe yapılandırması
STRIPE_API_KEY = "sk_test_51XXXXXXXXXXXXXXXXXXXXXX"  # Test API anahtarı - gerçek anahtarla değiştirin
STRIPE_PUBLIC_KEY = "pk_test_51XXXXXXXXXXXXXXXXXXXXXX"  # Test Public API anahtarı
stripe.api_key = STRIPE_API_KEY
app.config['STRIPE_PUBLIC_KEY'] = STRIPE_PUBLIC_KEY

# CSRF koruması
csrf = CSRFProtect(app)

# Vercel ortamında CSRF korumasını yapılandır
if os.environ.get('VERCEL_ENV'):
    app.config['WTF_CSRF_CHECK_DEFAULT'] = False  # CSRF doğrulamasını geçici olarak devre dışı bırak
    # veya
    app.config['WTF_CSRF_TIME_LIMIT'] = None  # CSRF token süre sınırlamasını kaldır
    app.config['WTF_CSRF_SSL_STRICT'] = False  # SSL gerektirme

# JWT konfigurasyonu
app.config['JWT_SECRET_KEY'] = secrets.token_hex(32)  # JWT için farklı bir güvenli anahtar
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)  # Token geçerlilik süresi
jwt = JWTManager(app)

# Gemini API anahtarı ve endpoint
GEMINI_API_KEY = "AIzaSyCE8YbG-RnskAL51MmzAKthVme7l-ZEaRs"  # Gerçek API anahtarınızla değiştirin
GEMINI_API_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={GEMINI_API_KEY}"

# Veritabanı ayarları
DB_PATH = 'kan_tahlil_app.db'

# Vercel ortamında PostgreSQL bağlantısı için
if os.environ.get('VERCEL_ENV') or os.environ.get('DATABASE_URL'):
    # PostgreSQL bağlantısı
    DB_URL = os.environ.get('DATABASE_URL', 'postgresql://postgres.vadawhtloelyiiibhtsh:tJWr61Nx0StOnbHs@aws-0-eu-central-1.pooler.supabase.com:6543/postgres')
    if DB_URL.startswith("postgres://"):
        DB_URL = DB_URL.replace("postgres://", "postgresql://", 1)
    DB_PATH = DB_URL

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

# Veritabanı yardımcı fonksiyonu
def db_connect():
    """PostgreSQL veya SQLite veritabanı bağlantısı oluşturur"""
    if DB_PATH.startswith('postgresql://'):
        # PostgreSQL bağlantısı
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(DB_PATH)
        conn.cursor_factory = psycopg2.extras.DictCursor  # dict benzeri sonuçlar döndürmesi için
        return conn
    else:
        # SQLite bağlantısı
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

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

def init_db():
    """Veritabanını ve tabloları oluşturur"""
    if DB_PATH.startswith('postgresql://'):
        # PostgreSQL bağlantısı kullan
        try:
            conn = db_connect()
            c = conn.cursor()
            
            # Önce kullanıcılar tablosunu kontrol et
            c.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = 'users'
            );
            """)
            table_exists = c.fetchone()[0]
            
            if not table_exists:
                print("PostgreSQL veritabanında tablolar oluşturuluyor...")
                
                # Kullanıcılar tablosu
                c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE,
                    role VARCHAR(20) DEFAULT 'user',
                    login_count INTEGER DEFAULT 0,
                    subscription_plan VARCHAR(50) DEFAULT 'free',
                    stripe_customer_id TEXT,
                    subscription_status VARCHAR(50) DEFAULT 'active',
                    subscription_end_date TIMESTAMP
                )
                ''')
                
                # Tahlil kayıtları tablosu
                c.execute('''
                CREATE TABLE IF NOT EXISTS analyses (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    file_name TEXT,
                    analysis_text TEXT,
                    analysis_result TEXT,
                    analysis_json TEXT,
                    analysis_type VARCHAR(50) DEFAULT 'kan',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Tahlil değerleri tablosu
                c.execute('''
                CREATE TABLE IF NOT EXISTS test_values (
                    id SERIAL PRIMARY KEY,
                    analysis_id INTEGER REFERENCES analyses(id) ON DELETE CASCADE,
                    parameter_name TEXT,
                    value REAL,
                    unit TEXT,
                    ref_min REAL,
                    ref_max REAL,
                    is_normal BOOLEAN,
                    category TEXT,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Abonelikler tablosu
                c.execute('''
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    plan_type TEXT NOT NULL,
                    stripe_subscription_id TEXT,
                    stripe_customer_id TEXT,
                    status TEXT NOT NULL,
                    current_period_start TIMESTAMP,
                    current_period_end TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Faturalar tablosu
                c.execute('''
                CREATE TABLE IF NOT EXISTS invoices (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    subscription_id INTEGER REFERENCES subscriptions(id),
                    stripe_invoice_id TEXT,
                    amount REAL,
                    currency TEXT DEFAULT 'TRY',
                    status TEXT,
                    invoice_date TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                # Kullanım istatistikleri tablosu
                c.execute('''
                CREATE TABLE IF NOT EXISTS usage_stats (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id),
                    analysis_count INTEGER DEFAULT 0,
                    month INTEGER,
                    year INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                ''')
                
                conn.commit()
                
                # Admin kullanıcısını oluştur
                admin_password = hash_password("admin123")
                c.execute("INSERT INTO users (username, password, email, role) VALUES (%s, %s, %s, %s)", 
                        ("admin", admin_password, "admin@meditahlil.com", "admin"))
                conn.commit()
                print("PostgreSQL tabloları ve admin kullanıcısı oluşturuldu.")
            else:
                print("PostgreSQL tabloları zaten mevcut.")
            
            conn.close()
            
        except Exception as e:
            print(f"PostgreSQL veritabanı oluşturma hatası: {str(e)}")
            raise
    else:
        # SQLite bağlantısı
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

# Admin gerekli dekoratör
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfayı görüntülemek için giriş yapmalısınız!', 'warning')
            return redirect(url_for('login'))
        
        try:
            conn = db_connect()
            c = conn.cursor()
            
            if DB_PATH.startswith('postgresql://'):
                c.execute("SELECT role FROM users WHERE id = %s", (session['user_id'],))
            else:
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
    conn = db_connect()
    c = conn.cursor()
    
    if DB_PATH.startswith('postgresql://'):
        analysis_count = c.execute('SELECT COUNT(*) FROM analyses WHERE user_id = %s', (user_id,)).fetchone()[0]
        login_count = c.execute('SELECT login_count FROM users WHERE id = %s', (user_id,)).fetchone()['login_count']
    else:
        analysis_count = c.execute('SELECT COUNT(*) FROM analyses WHERE user_id = ?', (user_id,)).fetchone()[0]
        login_count = c.execute('SELECT login_count FROM users WHERE id = ?', (user_id,)).fetchone()['login_count']
    
    conn.close()
    
    # Eğer kullanıcı ilk kez giriş yaptıysa veya hiç analizi yoksa yeni kullanıcı olarak kabul et
    return analysis_count == 0 or login_count <= 2

# Kullanıcının giriş sayısını arttır
def increment_login_count(user_id):
    conn = db_connect()
    c = conn.cursor()
    
    if DB_PATH.startswith('postgresql://'):
        c.execute('UPDATE users SET login_count = login_count + 1 WHERE id = %s', (user_id,))
    else:
        c.execute('UPDATE users SET login_count = login_count + 1 WHERE id = ?', (user_id,))
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Ana sayfa"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Kullanıcı girişi"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = db_connect()
        c = conn.cursor()
        
        if DB_PATH.startswith('postgresql://'):
            c.execute("SELECT id, username, password, role FROM users WHERE username = %s", (username,))
        else:
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
        
        conn = db_connect()
        c = conn.cursor()
        
        try:
            if DB_PATH.startswith('postgresql://'):
                c.execute("INSERT INTO users (username, password, email) VALUES (%s, %s, %s)", 
                        (username, hashed_password, email))
            else:
                c.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", 
                        (username, hashed_password, email))
            
            conn.commit()
            flash('Kaydınız başarıyla oluşturuldu! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            # PostgreSQL ve SQLite için farklı hata kodları
            if DB_PATH.startswith('postgresql://'):
                if 'duplicate key' in str(e).lower():
                    flash('Bu kullanıcı adı veya e-posta zaten kullanılıyor!', 'danger')
                else:
                    flash('Kayıt sırasında bir hata oluştu!', 'danger')
                    print(f"Kayıt hatası: {e}")
            else:
                if isinstance(e, sqlite3.IntegrityError):
                    flash('Bu kullanıcı adı veya e-posta zaten kullanılıyor!', 'danger')
                else:
                    flash('Kayıt sırasında bir hata oluştu!', 'danger')
                    print(f"Kayıt hatası: {e}")
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
    conn = db_connect()
    c = conn.cursor()
    
    if DB_PATH.startswith('postgresql://'):
        c.execute("SELECT * FROM analyses WHERE user_id = %s ORDER BY created_at DESC", (session['user_id'],))
    else:
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
    
    # Kullanıcının üyelik bilgilerini ve bu aydaki analiz sayısını al
    conn = db_connect()
    c = conn.cursor()
    
    # Kullanıcı bilgilerini al
    if DB_PATH.startswith('postgresql://'):
        c.execute("SELECT subscription_plan FROM users WHERE id = %s", (session['user_id'],))
    else:
        c.execute("SELECT subscription_plan FROM users WHERE id = ?", (session['user_id'],))
        
    user = c.fetchone()
    current_plan = user['subscription_plan'] if user else 'free'
    
    # Plan bilgilerini al
    plan_name = SUBSCRIPTION_PLANS[current_plan]['name']
    analysis_limit = SUBSCRIPTION_PLANS[current_plan]['analysis_limit']
    
    # Sonsuz limit ise, kalan hakkı 999 olarak göster (infinity işareti kullanmak yerine)
    if analysis_limit == float('inf'):
        remaining_analyses = 999
    else:
        # Bu aydaki analiz sayısını hesapla
        current_month = datetime.now().month
        current_year = datetime.now().year
        
        if DB_PATH.startswith('postgresql://'):
            c.execute("""
                SELECT COUNT(*) as count FROM analyses 
                WHERE user_id = %s 
                AND EXTRACT(MONTH FROM created_at) = %s 
                AND EXTRACT(YEAR FROM created_at) = %s
            """, (session['user_id'], current_month, current_year))
            monthly_count = c.fetchone()[0]
        else:
            c.execute("""
                SELECT COUNT(*) as count FROM analyses 
                WHERE user_id = ? 
                AND strftime('%m', created_at) = ? 
                AND strftime('%Y', created_at) = ?
            """, (session['user_id'], f"{current_month:02d}", str(current_year)))
            monthly_count = c.fetchone()['count']
            
        remaining_analyses = max(0, analysis_limit - monthly_count)
    
    conn.close()
    
    if request.method == 'POST':
        # Eğer kalan hak yoksa ve sınırsız plan değilse işlemi engelle
        if remaining_analyses <= 0 and current_plan not in ['premium', 'family']:
            flash('Bu ay için tahlil hakkınız dolmuştur. Daha fazla analiz yapmak için lütfen üyeliğinizi yükseltin.', 'warning')
            return redirect(url_for('subscription_plans'))
            
        file = request.files.get('pdf_file')
        if not file or not file.filename.lower().endswith('.pdf'):
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"error": "Lütfen bir PDF dosyası yükleyin."}), 400
            flash('Lütfen bir PDF dosyası yükleyin.', 'danger')
            return redirect(url_for('analyze'))
        
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
        prompt = f"""Bir doktor gibi aşağıdaki kan tahlili raporunu Türkçe olarak yorumla ve JSON formatında yapılandırılmış bir çıktı oluştur.
        
Lütfen şunları yap:

1. Tüm önemli değerleri ve referans aralıklarını analiz et
2. Normal dışı değerleri belirle ve yorumla
3. Değerlerle ilgili kısa, anlaşılır yorumlar yap
4. Bulgulara dayalı öneriler sun
5. Değerleri gruplandır (örn: hematoloji, biyokimya, vb.)
6. Yanıt aşağıdaki JSON formatında olmalı:

```json
{{
  "summary": "Genel değerlendirme metni",
  "abnormal_count": 3, // Normal dışı değer sayısı
  "test_groups": [
    {{
      "group_name": "Hematoloji",
      "parameters": [
        {{
          "name": "Hemoglobin",
          "value": 14.2,
          "unit": "g/dL",
          "ref_min": 13.5,
          "ref_max": 17.5,
          "is_normal": true,
          "comment": "Normal sınırlar içinde"
        }},
        // Diğer parametreler...
      ]
    }},
    // Diğer gruplar...
  ],
  "recommendations": [
    "Öneriler liste halinde",
    "Başka bir öneri"
  ],
  "general_analysis": "Tahlil sonuçlarının özet yorumu"
}}
```

JSON dışında ek metin veya açıklama ekleme, yalnızca JSON formatında yanıt ver.

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
                "temperature": 0.1,  # Yapılandırılmış veri için daha düşük sıcaklık
                "maxOutputTokens": 4000,  # Daha uzun yanıtlar için token sayısını artırıyoruz
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
                result_raw = response_data["candidates"][0]["content"]["parts"][0]["text"]
                
                # Yanıt boş mu kontrol et
                if not result_raw or not result_raw.strip():
                    print("API yanıtı boş")
                    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                        return jsonify({"error": "API yanıtı boş. Lütfen tekrar deneyin."}), 500
                    flash('API yanıtı boş. Lütfen tekrar deneyin.', 'danger')
                    return redirect(url_for('analyze'))
                
                # JSON formatını temizleyelim (```json ve ``` ifadelerini kaldırma)
                result_clean = result_raw.replace("```json", "").replace("```", "").strip()
                
                try:
                    # JSON formatını parse et
                    analysis_json = json.loads(result_clean)
                    
                    # JSON'ın doğru formatta olup olmadığını kontrol et
                    if not isinstance(analysis_json, dict):
                        raise ValueError("API yanıtı geçerli bir JSON nesnesi döndürmedi")
                        
                    # Okunabilir insan formatında metni oluştur
                    result_text = f"""### GENEL DEĞERLENDİRME
{analysis_json.get('summary', 'Değerlendirme yapılamadı.')}

### DETAYLI ANALİZ
"""
                    # Test gruplarını ekle
                    for group in analysis_json.get('test_groups', []):
                        result_text += f"\n## {group.get('group_name', 'Genel')}\n"
                        for param in group.get('parameters', []):
                            status = "NORMAL" if param.get('is_normal', True) else "DİKKAT - NORMAL DIŞI"
                            result_text += f"* {param.get('name', '')}: {param.get('value', '')} {param.get('unit', '')} " \
                                          f"(Referans: {param.get('ref_min', '')} - {param.get('ref_max', '')} {param.get('unit', '')}) " \
                                          f"[{status}]\n  {param.get('comment', '')}\n"
                    
                    # Önerileri ekle 
                    result_text += "\n### ÖNERİLER\n"
                    for rec in analysis_json.get('recommendations', []):
                        result_text += f"* {rec}\n"
                    
                    # Genel analizi ekle
                    if 'general_analysis' in analysis_json:
                        result_text += f"\n### SONUÇ\n{analysis_json.get('general_analysis', '')}"
                    
                    # Debug için bir kısmını yazdır
                    print(f"JSON yanıt işlendi.")
                    print(f"Anormal değer sayısı: {analysis_json.get('abnormal_count', 0)}")
                    print(f"Grup sayısı: {len(analysis_json.get('test_groups', []))}")
                    
                    # Veritabanına kaydet
                    conn = db_connect()
                    c = conn.cursor()
                    
                    # Ana analizi kaydet
                    if DB_PATH.startswith('postgresql://'):
                        c.execute(
                            """INSERT INTO analyses 
                               (user_id, file_name, analysis_text, analysis_result, analysis_json, analysis_type) 
                               VALUES (%s, %s, %s, %s, %s, %s) RETURNING id""",
                            (session['user_id'], file.filename, text[:1000], result_text, json.dumps(analysis_json), 'kan')
                        )
                        analysis_id = c.fetchone()[0]
                    else:
                        c.execute(
                            """INSERT INTO analyses 
                               (user_id, file_name, analysis_text, analysis_result, analysis_json, analysis_type) 
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (session['user_id'], file.filename, text[:1000], result_text, json.dumps(analysis_json), 'kan')
                        )
                        analysis_id = c.lastrowid
                    
                    # Test değerlerini kaydet
                    for group in analysis_json.get('test_groups', []):
                        for param in group.get('parameters', []):
                            try:
                                # Değerleri sayısal formata çevir (gerekirse)
                                value = float(param.get('value', 0)) if param.get('value') is not None else None
                                ref_min = float(param.get('ref_min', 0)) if param.get('ref_min') is not None else None
                                ref_max = float(param.get('ref_max', 0)) if param.get('ref_max') is not None else None
                                
                                # Veritabanına kaydet
                                if DB_PATH.startswith('postgresql://'):
                                    c.execute(
                                        """INSERT INTO test_values 
                                           (analysis_id, parameter_name, value, unit, ref_min, ref_max, is_normal, category, description) 
                                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)""",
                                        (
                                            analysis_id,
                                            param.get('name', ''),
                                            value,
                                            param.get('unit', ''),
                                            ref_min,
                                            ref_max,
                                            True if param.get('is_normal', True) else False,
                                            group.get('group_name', 'Genel'),
                                            param.get('comment', '')
                                        )
                                    )
                                else:
                                    c.execute(
                                        """INSERT INTO test_values 
                                           (analysis_id, parameter_name, value, unit, ref_min, ref_max, is_normal, category, description) 
                                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                                        (
                                            analysis_id,
                                            param.get('name', ''),
                                            value,
                                            param.get('unit', ''),
                                            ref_min,
                                            ref_max,
                                            1 if param.get('is_normal', True) else 0,
                                            group.get('group_name', 'Genel'),
                                            param.get('comment', '')
                                        )
                                    )
                            except (ValueError, TypeError) as e:
                                print(f"Değer dönüştürme hatası: {e} - Parametre: {param.get('name', 'Bilinmeyen')}")
                                # Hataya rağmen diğer değerleri kaydetmeye devam et
                    
                    conn.commit()
                    conn.close()
                    
                except json.JSONDecodeError as e:
                    print(f"JSON parse hatası: {e}")
                    print(f"Alınan JSON: {result_clean[:500]}...")
                    # Parse edilemiyorsa, ham metni kaydet
                    conn = db_connect()
                    c = conn.cursor()
                    
                    if DB_PATH.startswith('postgresql://'):
                        c.execute(
                            "INSERT INTO analyses (user_id, file_name, analysis_text, analysis_result) VALUES (%s, %s, %s, %s) RETURNING id",
                            (session['user_id'], file.filename, text[:1000], result_raw)
                        )
                        analysis_id = c.fetchone()[0]
                    else:
                        c.execute(
                            "INSERT INTO analyses (user_id, file_name, analysis_text, analysis_result) VALUES (?, ?, ?, ?)",
                            (session['user_id'], file.filename, text[:1000], result_raw)
                        )
                        analysis_id = c.lastrowid
                        
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
    
    return render_template('analyze.html',
                          current_plan=current_plan,
                          plan_name=plan_name,
                          analysis_limit=analysis_limit,
                          remaining_analyses=remaining_analyses)
    return render_template('analyze.html')

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
    
    # Test değerlerini getir (Yeni)
    c.execute("""
        SELECT * FROM test_values 
        WHERE analysis_id = ? 
        ORDER BY category, parameter_name
    """, (analysis_id,))
    test_values = [dict(row) for row in c.fetchall()]
    
    # Kategorilere göre değerleri grupla (Yeni)
    categories = {}
    abnormal_values = []
    for value in test_values:
        category = value['category']
        if category not in categories:
            categories[category] = []
        categories[category].append(value)
        
        # Normal dışı değerleri ayrıca topla
        if not value['is_normal']:
            abnormal_values.append(value)
    
    # Analiz JSON'ını parse et
    analysis_json = {}
    if analysis['analysis_json']:
        try:
            analysis_json = json.loads(analysis['analysis_json'])
        except json.JSONDecodeError:
            pass  # JSON parse edilemezse, boş dict kullan
    
    # Kullanıcının geçmiş analizlerini getir (trend analizi için)
    c.execute("""
        SELECT a.id, a.created_at 
        FROM analyses a 
        WHERE a.user_id = ? AND a.id != ? 
        ORDER BY a.created_at DESC 
        LIMIT 5
    """, (session['user_id'], analysis_id))
    previous_analyses = c.fetchall()
    
    # Eğer geçmiş analizler varsa, karşılaştırma için değerleri hazırla
    comparison_data = {}
    if previous_analyses:
        # En son analizden başlayarak karşılaştırma verilerini topla
        for prev_analysis in previous_analyses:
            c.execute("""
                SELECT parameter_name, value, created_at 
                FROM test_values 
                WHERE analysis_id = ?
            """, (prev_analysis['id'],))
            prev_values = c.fetchall()
            
            for pv in prev_values:
                param_name = pv['parameter_name']
                if param_name not in comparison_data:
                    comparison_data[param_name] = []
                
                comparison_data[param_name].append({
                    'date': prev_analysis['created_at'].split()[0],  # Sadece tarih kısmını al
                    'value': pv['value']
                })
    
    conn.close()
    
    # Ek bilgileri şablona aktar
    return render_template('result.html', 
                          analysis=analysis,
                          test_values=test_values,
                          categories=categories,
                          abnormal_values=abnormal_values,
                          analysis_json=analysis_json,
                          comparison_data=comparison_data)

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

@app.route('/init-db')
def initialize_database():
    """Veritabanını başlat (geliştirme için)"""
    if os.environ.get('VERCEL_ENV') or request.headers.get('X-Vercel-Deployment-Url'):
        try:
            init_db()
            return jsonify({"success": True, "message": "Veritabanı tabloları başarıyla oluşturuldu."})
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
    else:
        return jsonify({"success": False, "message": "Bu route sadece Vercel ortamında kullanılabilir."}), 403

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

# Vercel environment için veritabanını oluştur
if os.environ.get('VERCEL_ENV'):
    try:
        print("Vercel ortamında çalışıyor, veritabanı tabloları oluşturuluyor...")
        init_db()
        print("Veritabanı tabloları başarıyla oluşturuldu.")
    except Exception as e:
        print(f"Vercel veritabanı başlatma hatası: {str(e)}")

if __name__ == '__main__':
    try:
        # Veritabanı bilgilerini yazdır
        if DB_PATH.startswith('postgresql://'):
            print(f"PostgreSQL veritabanı kullanılıyor: {DB_PATH}")
        else:
            print(f"SQLite veritabanı kullanılıyor: {DB_PATH}")
            
        # Veritabanını başlat
        init_db()
        # Uygulamayı çalıştır
        app.run(debug=True)
    except Exception as e:
        print(f"Uygulama başlatma hatası: {e}")
