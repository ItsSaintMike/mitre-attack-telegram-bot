import os
import logging
from dotenv import load_dotenv

load_dotenv()

class Config:
    BOT_TOKEN = os.getenv('BOT_TOKEN')
    MITRE_API_URL = os.getenv('MITRE_API_URL')
    MITRE_ATTACK_URL = os.getenv('MITRE_ATTACK_URL')
    DB_PATH = os.getenv('DB_PATH', 'data/mitre_data.db')
    UPDATE_INTERVAL = int(os.getenv('UPDATE_INTERVAL', 86400))
    MAX_SEARCH_RESULTS = int(os.getenv('MAX_SEARCH_RESULTS', 15))
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')

    @staticmethod
    def setup_logging():
        os.makedirs('logs', exist_ok=True)
        logging.basicConfig(
            level=getattr(logging, Config.LOG_LEVEL),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('logs/bot.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger(__name__)

if not Config.BOT_TOKEN:
    raise ValueError("BOT_TOKEN не найден в .env файле!")
