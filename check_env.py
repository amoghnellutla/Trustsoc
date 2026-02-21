import os
from dotenv import load_dotenv

load_dotenv()

print("DATABASE_URL:", os.getenv("DATABASE_URL"))
print("VIRUSTOTAL_API_KEY exists:", os.getenv("VIRUSTOTAL_API_KEY") is not None)
print("ABUSEIPDB_API_KEY exists:", os.getenv("ABUSEIPDB_API_KEY") is not None)
print("OTX_API_KEY exists:", os.getenv("OTX_API_KEY") is not None)
print("ENVIRONMENT:", os.getenv("ENVIRONMENT"))
