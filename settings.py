from dotenv import load_dotenv
import os


#Load API keys from .env

load_dotenv()

hibp_key = os.getenv('HIBP_KEY')
censys_key = os.getenv('CENSYS_KEY')
censys_secret = os.getenv('CENSYS_SECRET')
ipinfo_key = os.getenv('IPINFO_SECRET')
shodan_key = os.getenv('SHODAN_KEY')
otx_key = os.getenv('OTX_KEY')
aipdb_key = os.getenv('AIPDB_KEY')




