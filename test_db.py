import os
import psycopg2
from psycopg2 import sql

# PostgreSQL bağlantı bilgileri
DB_URL = 'postgresql://postgres.vadawhtloelyiiibhtsh:tJWr61Nx0StOnbHs@aws-0-eu-central-1.pooler.supabase.com:6543/postgres'

def test_connection():
    """PostgreSQL bağlantısını test et"""
    try:
        print("PostgreSQL veritabanına bağlanılıyor...")
        conn = psycopg2.connect(DB_URL)
        cursor = conn.cursor()
        print("Bağlantı başarılı!")
        
        # PostgreSQL sürümünü kontrol et
        cursor.execute("SELECT version();")
        db_version = cursor.fetchone()
        print(f"PostgreSQL sürümü: {db_version[0]}")
        
        # Mevcut tabloları listele
        print("\nMevcut tablolar:")
        cursor.execute("""
            SELECT table_name 
            FROM information_schema.tables 
            WHERE table_schema = 'public'
            ORDER BY table_name;
        """)
        tables = cursor.fetchall()
        if tables:
            for table in tables:
                print(f"- {table[0]}")
        else:
            print("Hiç tablo bulunamadı.")
        
        # Test tablosunu oluştur
        print("\nTest tablosu oluşturuluyor...")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS test_table (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()
        print("Test tablosu oluşturuldu veya zaten mevcut.")
        
        # Test verisi ekle
        print("\nTest verisi ekleniyor...")
        cursor.execute("""
            INSERT INTO test_table (name) VALUES (%s) RETURNING id;
        """, ('Test veri ' + os.urandom(4).hex(),))
        new_id = cursor.fetchone()[0]
        conn.commit()
        print(f"Test verisi eklendi, ID: {new_id}")
        
        # Verileri oku
        print("\nTest tablosundaki veriler:")
        cursor.execute("SELECT id, name, created_at FROM test_table ORDER BY created_at DESC LIMIT 5;")
        rows = cursor.fetchall()
        for row in rows:
            print(f"ID: {row[0]}, İsim: {row[1]}, Tarih: {row[2]}")
        
        # Bağlantıyı kapat
        cursor.close()
        conn.close()
        print("\nBağlantı kapatıldı.")
        print("PostgreSQL testi başarıyla tamamlandı!")
        return True
        
    except Exception as e:
        print(f"PostgreSQL bağlantı hatası: {e}")
        return False

if __name__ == "__main__":
    test_connection() 