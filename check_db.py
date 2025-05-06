import sqlite3
from datetime import datetime

def check_analyses():
    conn = sqlite3.connect('kan_tahlil_app.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    print("Son 5 Analiz:")
    c.execute("SELECT id, user_id, file_name, created_at FROM analyses ORDER BY created_at DESC LIMIT 5")
    analyses = c.fetchall()
    for analysis in analyses:
        print(f"ID: {analysis['id']}, User ID: {analysis['user_id']}, File: {analysis['file_name']}, Date: {analysis['created_at']}")
    
    print("\nKullanıcı başına analiz sayısı:")
    c.execute("""
        SELECT users.username, COUNT(analyses.id) as count 
        FROM users 
        LEFT JOIN analyses ON users.id = analyses.user_id 
        GROUP BY users.id
    """)
    user_counts = c.fetchall()
    for user in user_counts:
        print(f"Kullanıcı: {user['username']}, Analiz Sayısı: {user['count']}")
    
    conn.close()

if __name__ == "__main__":
    check_analyses() 