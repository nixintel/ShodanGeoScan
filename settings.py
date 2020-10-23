from dotenv import load_dotenv
import os


#Load API keys from .env

load_dotenv()

shodan_key = os.getenv('SHODAN_KEY')
aipdb_key = os.getenv('AIPDB_KEY')




