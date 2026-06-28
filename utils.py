import re
from datetime import datetime
from typing import List, Dict

def format_technique_id(tech_id: str) -> str:
    if not tech_id:
        return ""
    match = re.search(r'[Tt]\d{4}(?:\.\d{3})?', tech_id)
    return match.group(0).upper() if match else tech_id

def format_description(description: str, max_length: int = 200) -> str:
    if not description:
        return "Описание отсутствует"
    if len(description) <= max_length:
        return description
    return description[:max_length] + "..."

def get_time_ago(date_string: str) -> str:
    try:
        date_str = date_string.replace('Z', '+00:00')
        date = datetime.fromisoformat(date_str)
        now = datetime.now()
        diff = now - date

        if diff.days > 30:
            return f"{diff.days // 30} месяцев назад"
        elif diff.days > 0:
            return f"{diff.days} дней назад"
        elif diff.seconds > 3600:
            return f"{diff.seconds // 3600} часов назад"
        elif diff.seconds > 60:
            return f"{diff.seconds // 60} минут назад"
        else:
            return "только что"
    except:
        return date_string

def analyze_malware_behavior(techniques: List[Dict]) -> Dict:
    """Группирует техники по тактикам"""
    behavior = {}
    for tech in techniques:
        tactic = tech.get('tactic_name', 'Неизвестная тактика')
        if tactic not in behavior:
            behavior[tactic] = []
        behavior[tactic].append({
            'id': tech['id'],
            'name': tech['name']
        })
    return behavior

def generate_attack_chain(techniques: List[Dict]) -> str:
    """Генерирует цепочку атак на русском"""
    # Соответствие английских названий тактик русским
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

    chain_order = [
        'Reconnaissance', 'Resource Development', 'Initial Access',
        'Execution', 'Persistence', 'Privilege Escalation',
        'Defense Evasion', 'Credential Access', 'Discovery',
        'Lateral Movement', 'Collection', 'Command and Control',
        'Exfiltration', 'Impact'
    ]

    behavior = analyze_malware_behavior(techniques)
    chain = []

    for phase in chain_order:
        if phase in behavior:
            # Переводим название тактики на русский
            russian_phase = tactic_translation.get(phase, phase)
            chain.append(f"🔹 <b>{russian_phase}</b>")
            for tech in behavior[phase]:
                chain.append(f"   • <b>{tech['id']}</b> - {tech['name']}")
            chain.append("")

    if not chain:
        return "⚠️ Не удалось построить цепочку атак"

    return "\n".join(chain)

def generate_yara_hint(technique_id: str) -> str:
    """Подсказки для YARA правил на русском"""
    hints = {
        'T1059.001': '🔍 Ищите PowerShell команды с -e (base64) или -enc',
        'T1059.003': '🔍 Ищите cmd.exe /c с подозрительными командами',
        'T1105': '🔍 Ищите HTTP запросы к доменам с .exe, .dll, .ps1',
        'T1036': '🔍 Ищите процессы с именами системных из нестандартных путей',
        'T1003': '🔍 Ищите обращение к LSASS (procdump, mimikatz)',
        'T1027': '🔍 Ищите упакованные секции или высокую энтропию',
        'T1071': '🔍 Ищите C2 трафик с нестандартными User-Agent',
        'T1566': '🔍 Ищите фишинговые письма с вложениями или ссылками',
        'T1547': '🔍 Ищите изменения в автозагрузке (Run ключи, службы)',
        'T1136': '🔍 Ищите создание новых пользователей или групп',
        'T1059': '🔍 Ищите выполнение команд через интерпретаторы',
        'T1047': '🔍 Ищите выполнение через WMI',
        'T1082': '🔍 Ищите команды сбора информации о системе',
        'T1087': '🔍 Ищите команды перечисления учетных записей',
        'T1482': '🔍 Ищите команды обнаружения доменных доверий',
        'T1555': '🔍 Ищите доступ к хранилищам паролей',
        'T1110': '🔍 Ищите попытки брутфорса или подбора паролей',
        'T1078': '🔍 Ищите использование легитимных учетных записей',
        'T1218': '🔍 Ищите запуск через системные утилиты',
        'T1204': '🔍 Ищите запуск через фишинг или социальную инженерию'
    }
    return hints.get(technique_id, '📖 Изучите документацию MITRE для создания YARA правила')

def is_technique_id(text: str) -> bool:
    """Проверяет, является ли текст ID техники MITRE"""
    pattern = r'^[Tt]\d{4}(?:\.\d{3})?$'
    return bool(re.match(pattern, text.strip()))

def normalize_query(query: str) -> str:
    """Нормализует поисковый запрос (убирает лишнее, приводит к нижнему регистру)"""
    query = query.strip().lower()
    # Убираем множественные пробелы
    query = re.sub(r'\s+', ' ', query)
    return query
