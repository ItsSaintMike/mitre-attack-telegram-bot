import os
import csv
import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
from config import Config

class Database:
    def __init__(self):
        self.db_path = Config.DB_PATH
        self.translations = {}
        self.init_db()
        self.load_russian_translations()

    def init_db(self):
        os.makedirs('data', exist_ok=True)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS techniques (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    tactic_id TEXT,
                    tactic_name TEXT,
                    platform TEXT,
                    url TEXT,
                    created_date TEXT,
                    modified_date TEXT,
                    is_deprecated INTEGER DEFAULT 0
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tactics (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT,
                    url TEXT
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS malware_techniques (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    malware_name TEXT NOT NULL,
                    technique_id TEXT NOT NULL,
                    FOREIGN KEY (technique_id) REFERENCES techniques(id)
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS updates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    update_date TEXT NOT NULL,
                    new_techniques_count INTEGER,
                    modified_techniques_count INTEGER
                )
            ''')

            cursor.execute('CREATE INDEX IF NOT EXISTS idx_techniques_name ON techniques(name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_techniques_tactic ON techniques(tactic_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_malware_name ON malware_techniques(malware_name)')
            conn.commit()

    def load_russian_translations(self, csv_path='translations.csv'):
        """Загружает русские переводы из CSV файла"""
        self.translations = {}
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.translations[row['technique_id']] = row['russian_name']
            print(f"✅ Загружено {len(self.translations)} переводов на русский")
        except FileNotFoundError:
            print("⚠️ Файл translations.csv не найден, используем английские названия")
            self.translations = {}
        except Exception as e:
            print(f"⚠️ Ошибка загрузки переводов: {e}")
            self.translations = {}

    def get_russian_name(self, tech_id: str) -> str:
        """Возвращает русское название техники, если есть"""
        return self.translations.get(tech_id, '')

    def get_russian_tactic(self, tactic_name: str) -> str:
        """Переводит название тактики на русский"""
        tactic_translation = {
            'Reconnaissance': 'Разведка',
            'Resource Development': 'Разработка ресурсов',
            'Initial Access': 'Начальный доступ',
            'Execution': 'Выполнение',
            'Persistence': 'Закрепление',
            'Privilege Escalation': 'Повышение привилегий',
            'Defense Evasion': 'Обход защиты',
            'Credential Access': 'Доступ к учетным данным',
            'Discovery': 'Обнаружение',
            'Lateral Movement': 'Горизонтальное перемещение',
            'Collection': 'Сбор данных',
            'Command and Control': 'Командование и управление',
            'Exfiltration': 'Эксфильтрация',
            'Impact': 'Воздействие'
        }
        return tactic_translation.get(tactic_name, tactic_name)

    def save_technique(self, technique: Dict):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO techniques 
                (id, name, description, tactic_id, tactic_name, platform, url, created_date, modified_date, is_deprecated)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                technique.get('id'),
                technique.get('name'),
                technique.get('description'),
                technique.get('tactic_id'),
                technique.get('tactic_name'),
                technique.get('platform'),
                technique.get('url'),
                technique.get('created_date'),
                technique.get('modified_date'),
                1 if technique.get('is_deprecated', False) else 0
            ))
            conn.commit()

    def get_technique(self, technique_id: str) -> Optional[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM techniques WHERE id = ?', (technique_id,))
            result = cursor.fetchone()
            return dict(result) if result else None

    def get_techniques_by_tactic(self, tactic_name: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM techniques 
                WHERE tactic_name LIKE ? AND is_deprecated = 0
                ORDER BY name
            ''', (f'%{tactic_name}%',))
            return [dict(row) for row in cursor.fetchall()]

    def get_new_techniques_since(self, date: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT * FROM techniques 
                WHERE created_date > ? AND is_deprecated = 0
                ORDER BY created_date DESC
            ''', (date,))
            return [dict(row) for row in cursor.fetchall()]

    def search_techniques(self, query: str) -> List[Dict]:
        """Поиск техник с учетом русских переводов"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # 1. Ищем по ID (точное совпадение)
            if query.upper().startswith('T') and query.upper()[1:].isdigit():
                cursor.execute('''
                    SELECT * FROM techniques 
                    WHERE id = ? AND is_deprecated = 0
                ''', (query.upper(),))
                results = [dict(row) for row in cursor.fetchall()]
                if results:
                    return results
            
            # 2. Ищем по английским полям (название, описание, тактика)
            cursor.execute('''
                SELECT * FROM techniques 
                WHERE is_deprecated = 0 AND (
                    id LIKE ? OR 
                    name LIKE ? OR 
                    description LIKE ? OR
                    tactic_name LIKE ?
                )
                LIMIT ?
            ''', (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%', Config.MAX_SEARCH_RESULTS))
            
            results = [dict(row) for row in cursor.fetchall()]
            
            # 3. Если ничего не нашли, ищем по русским переводам
            if not results and self.translations:
                for tech_id, rus_name in self.translations.items():
                    if query.lower() in rus_name.lower():
                        tech = self.get_technique(tech_id)
                        if tech:
                            results.append(tech)
                            if len(results) >= Config.MAX_SEARCH_RESULTS:
                                break
            
            return results

    def save_tactics(self, tactics: List[Dict]):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for tactic in tactics:
                cursor.execute('''
                    INSERT OR REPLACE INTO tactics (id, name, description, url)
                    VALUES (?, ?, ?, ?)
                ''', (
                    tactic.get('id'),
                    tactic.get('name'),
                    tactic.get('description'),
                    tactic.get('url')
                ))
            conn.commit()

    def get_all_tactics(self) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM tactics ORDER BY name')
            return [dict(row) for row in cursor.fetchall()]

    def add_malware_techniques(self, malware_name: str, techniques: List[str]):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for tech_id in techniques:
                cursor.execute('''
                    INSERT OR IGNORE INTO malware_techniques (malware_name, technique_id)
                    VALUES (?, ?)
                ''', (malware_name, tech_id))
            conn.commit()

    def get_techniques_by_malware(self, malware_name: str) -> List[Dict]:
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute('''
                SELECT t.* FROM techniques t
                JOIN malware_techniques mt ON t.id = mt.technique_id
                WHERE mt.malware_name = ? AND t.is_deprecated = 0
                ORDER BY t.tactic_name, t.name
            ''', (malware_name,))
            return [dict(row) for row in cursor.fetchall()]

    def get_malware_by_technique(self, technique_id: str) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT malware_name 
                FROM malware_techniques 
                WHERE technique_id = ?
            ''', (technique_id,))
            return [row[0] for row in cursor.fetchall()]

    def get_all_malware(self) -> List[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT DISTINCT malware_name FROM malware_techniques ORDER BY malware_name')
            return [row[0] for row in cursor.fetchall()]

    def log_update(self, new_count: int, modified_count: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO updates (update_date, new_techniques_count, modified_techniques_count)
                VALUES (?, ?, ?)
            ''', (datetime.now().isoformat(), new_count, modified_count))
            conn.commit()

    def get_last_update_date(self) -> Optional[str]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT MAX(update_date) FROM updates')
            result = cursor.fetchone()
            return result[0] if result and result[0] else None
