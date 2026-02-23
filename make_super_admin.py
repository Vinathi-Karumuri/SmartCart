import sqlite3

conn = sqlite3.connect("smartcart.db")
cursor = conn.cursor()

cursor.execute("""
UPDATE admin
SET role = 'superadmin'
WHERE email = ?
""", ('vinathikarumuri@gmail.com',))

conn.commit()
conn.close()

print("👑 Super admin set successfully")