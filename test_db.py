import os
from dotenv import load_dotenv
import psycopg2

load_dotenv()

db_url = os.getenv("DATABASE_URL")

try:
    conn = psycopg2.connect(db_url)
    print("✅ Database connection successful!")
    conn.close()
except Exception as e:
    print("❌ Database connection failed:")
    print(e)
