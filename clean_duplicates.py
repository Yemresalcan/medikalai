import sqlite3
from datetime import datetime, timedelta

def clean_duplicates():
    conn = sqlite3.connect('kan_tahlil_app.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Aynı kullanıcı ve dosya adına sahip, 1 dakika içinde yapılan mükerrer kayıtları bul
    c.execute("""
        SELECT a1.id, a1.user_id, a1.file_name, a1.created_at
        FROM analyses a1
        INNER JOIN analyses a2 ON 
            a1.user_id = a2.user_id AND 
            a1.file_name = a2.file_name AND
            a1.id > a2.id AND
            ABS(JULIANDAY(a1.created_at) - JULIANDAY(a2.created_at)) * 24 * 60 <= 1
    """)
    duplicates = c.fetchall()
    
    print(f"Bulunan mükerrer kayıt sayısı: {len(duplicates)}")
    
    # Mükerrer kayıtları sil
    for dup in duplicates:
        print(f"Siliniyor: ID: {dup['id']}, User: {dup['user_id']}, File: {dup['file_name']}, Date: {dup['created_at']}")
        c.execute("DELETE FROM analyses WHERE id = ?", (dup['id'],))
    
    conn.commit()
    conn.close()
    print("Temizlik tamamlandı!")

if __name__ == "__main__":
    clean_duplicates() 