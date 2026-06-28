#!/usr/bin/env python3
import os
import sys
import time
import threading
import logging
from datetime import datetime, timedelta

import telebot
from telebot import types

from config import Config
from database import Database
from mitre_api import MitreAPI
from messages import Messages
from utils import (
    format_technique_id, format_description, get_time_ago,
    generate_attack_chain, generate_yara_hint, is_technique_id
)

logger = Config.setup_logging()

os.makedirs('data', exist_ok=True)
os.makedirs('logs', exist_ok=True)

db = Database()
mitre = MitreAPI()
bot = telebot.TeleBot(Config.BOT_TOKEN)
messages = Messages()

def get_pt_url(tech_id: str) -> str:
    return f"https://mitre.ptsecurity.com/ru-RU/{tech_id}?product=vm"

@bot.message_handler(commands=['start'])
def handle_start(message):
    keyboard = types.ReplyKeyboardMarkup(row_width=2, resize_keyboard=True)
    keyboard.add(
        types.KeyboardButton('/new'),
        types.KeyboardButton('/tactics'),
        types.KeyboardButton('/malware_list'),
        types.KeyboardButton('/help')
    )
    bot.send_message(
        message.chat.id,
        messages.WELCOME,
        reply_markup=keyboard,
        parse_mode='HTML'
    )
    logger.info(f"Start: {message.from_user.id}")

@bot.message_handler(commands=['help'])
def handle_help(message):
    bot.send_message(message.chat.id, messages.HELP, parse_mode='HTML')

@bot.message_handler(commands=['new'])
def handle_new(message):
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    new_techs = db.get_new_techniques_since(week_ago)

    if not new_techs:
        bot.send_message(message.chat.id, "🔍 За неделю новых техник нет.")
        return

    response = "🆕 <b>Новые техники (за 7 дней):</b>\n\n"
    for tech in new_techs[:10]:
        rus_name = db.get_russian_name(tech['id'])
        display_name = rus_name if rus_name else tech['name']
        tactic_rus = db.get_russian_tactic(tech['tactic_name'])
        pt_url = get_pt_url(tech['id'])

        response += f"• <b>{tech['id']}</b> - {display_name}\n"
        response += f"  📋 {tactic_rus}\n"
        response += f"  📅 {get_time_ago(tech['created_date'])}\n"
        response += f"  🔗 {pt_url}\n\n"

    if len(new_techs) > 10:
        response += f"... и еще {len(new_techs) - 10}"

    bot.send_message(message.chat.id, response, parse_mode='HTML', disable_web_page_preview=True)

@bot.message_handler(commands=['tactics'])
def handle_tactics(message):
    tactics = db.get_all_tactics()
    if not tactics:
        bot.send_message(message.chat.id, "⚠️ Тактики не загружены. Используйте /update")
        return

    response = "📋 <b>Тактики MITRE ATT&CK:</b>\n\n"
    for tactic in tactics:
        rus_name = db.get_russian_tactic(tactic['name'])
        response += f"<b>{tactic['id']}</b> - {rus_name}\n"
        desc = format_description(tactic.get('description', ''), 80)
        response += f"<i>{desc}</i>\n\n"

    bot.send_message(message.chat.id, response, parse_mode='HTML', disable_web_page_preview=True)

@bot.message_handler(commands=['tactic'])
def handle_tactic(message):
    msg = bot.send_message(
        message.chat.id,
        "📝 Введите название или ID тактики:\nПример: 'Initial Access', 'TA0001' или 'Начальный доступ'"
    )
    bot.register_next_step_handler(msg, process_tactic)

def process_tactic(message):
    query = message.text.strip()
    techniques = db.get_techniques_by_tactic(query)

    if not techniques:
        for eng, rus in [
            ('Reconnaissance', 'Разведка'),
            ('Resource Development', 'Разработка ресурсов'),
            ('Initial Access', 'Начальный доступ'),
            ('Execution', 'Выполнение'),
            ('Persistence', 'Закрепление'),
            ('Privilege Escalation', 'Повышение привилегий'),
            ('Defense Evasion', 'Обход защиты'),
            ('Credential Access', 'Доступ к учетным данным'),
            ('Discovery', 'Обнаружение'),
            ('Lateral Movement', 'Горизонтальное перемещение'),
            ('Collection', 'Сбор данных'),
            ('Command and Control', 'Командование и управление'),
            ('Exfiltration', 'Эксфильтрация'),
            ('Impact', 'Воздействие')
        ]:
            if query.lower() in rus.lower():
                techniques = db.get_techniques_by_tactic(eng)
                break

    if not techniques:
        bot.send_message(
            message.chat.id,
            f"❌ По тактике '{query}' ничего не найдено."
        )
        return

    response = f"📌 <b>Техники тактики {query}:</b>\n\n"
    for tech in techniques[:15]:
        rus_name = db.get_russian_name(tech['id'])
        display_name = rus_name if rus_name else tech['name']
        response += f"• <b>{tech['id']}</b> - {display_name}\n"

    if len(techniques) > 15:
        response += f"\n... и еще {len(techniques) - 15}"

    bot.send_message(message.chat.id, response, parse_mode='HTML')

@bot.message_handler(commands=['malware'])
def handle_malware(message):
    msg = bot.send_message(
        message.chat.id,
        "🦠 Введите название малвари:\nНапример: 'Emotet', 'TrickBot'"
    )
    bot.register_next_step_handler(msg, process_malware)

def process_malware(message):
    malware_name = message.text.strip()
    techniques = db.get_techniques_by_malware(malware_name)

    if not techniques:
        bot.send_message(
            message.chat.id,
            f"❌ Малварь '{malware_name}' не найдена.\n"
            f"Список: /malware_list\nДобавить: /add_malware"
        )
        return

    tech_list = ""
    for tech in techniques:
        rus_name = db.get_russian_name(tech['id'])
        display_name = rus_name if rus_name else tech['name']
        tech_list += f"  • <b>{tech['id']}</b> - {display_name}\n"

    attack_chain = generate_attack_chain(techniques)

    yara_hints = []
    for tech in techniques[:5]:
        yara_hints.append(f"• {tech['id']}: {generate_yara_hint(tech['id'])}")

    response = messages.MALWARE_TEMPLATE.format(
        malware_name=malware_name,
        count=len(techniques),
        techniques=tech_list,
        attack_chain=attack_chain,
        yara_hints="\n".join(yara_hints)
    )

    bot.send_message(message.chat.id, response, parse_mode='HTML', disable_web_page_preview=True)
    logger.info(f"Malware analyzed: {malware_name}")

@bot.message_handler(commands=['add_malware'])
def handle_add_malware(message):
    msg = bot.send_message(
        message.chat.id,
        "📝 Введите данные:\n<b>Название | TXXXX, TXXXX, TXXXX</b>\n\n"
        "Пример:\n<code>Emotet | T1059.001, T1105, T1036</code>",
        parse_mode='HTML'
    )
    bot.register_next_step_handler(msg, process_add_malware)

def process_add_malware(message):
    try:
        parts = message.text.split('|')
        if len(parts) != 2:
            bot.send_message(message.chat.id, "❌ Неверный формат. Используйте: Название | Техники")
            return

        malware_name = parts[0].strip()
        techniques = [t.strip() for t in parts[1].split(',')]

        invalid_techs = []
        for tech_id in techniques:
            if not db.get_technique(tech_id):
                invalid_techs.append(tech_id)

        if invalid_techs:
            bot.send_message(
                message.chat.id,
                f"⚠️ Техники не найдены: {', '.join(invalid_techs)}\n"
                f"Сначала обновите базу: /update"
            )
            return

        db.add_malware_techniques(malware_name, techniques)
        bot.send_message(
            message.chat.id,
            f"✅ <b>Малварь '{malware_name}' добавлена!</b>\n"
            f"📊 Техник: {len(techniques)}\n"
            f"🔍 /malware {malware_name}",
            parse_mode='HTML'
        )
        logger.info(f"Added malware: {malware_name}")

    except Exception as e:
        bot.send_message(message.chat.id, f"❌ Ошибка: {str(e)}")

@bot.message_handler(commands=['malware_list'])
def handle_malware_list(message):
    malware_list = db.get_all_malware()

    if not malware_list:
        bot.send_message(
            message.chat.id,
            "📭 В базе нет малварей.\nДобавьте через /add_malware"
        )
        return

    response = "🦠 <b>Список малварей:</b>\n\n"
    for malware in malware_list:
        techniques = db.get_techniques_by_malware(malware)
        response += f"• <b>{malware}</b> ({len(techniques)} техник)\n"

    response += "\n💡 /malware [название] - для анализа"

    bot.send_message(message.chat.id, response, parse_mode='HTML')

@bot.message_handler(commands=['update'])
def handle_update(message):
    status_msg = bot.send_message(
        message.chat.id,
        "🔄 <b>Обновление базы данных...</b>\n⏳ 10-30 секунд",
        parse_mode='HTML'
    )

    try:
        stix_data = mitre.fetch_attack_data()
        if not stix_data:
            bot.edit_message_text(
                "❌ Не удалось загрузить данные",
                chat_id=message.chat.id,
                message_id=status_msg.message_id
            )
            return

        parsed_data = mitre.parse_stix_data(stix_data)
        db.save_tactics(parsed_data['tactics'])

        new_count = 0
        for tech in parsed_data['techniques']:
            existing = db.get_technique(tech['id'])
            if not existing:
                new_count += 1
            db.save_technique(tech)

        db.log_update(new_count, 0)

        bot.edit_message_text(
            f"✅ <b>База обновлена!</b>\n\n"
            f"📊 Новых техник: {new_count}\n"
            f"📊 Всего техник: {len(parsed_data['techniques'])}\n"
            f"📋 Всего тактик: {len(parsed_data['tactics'])}\n"
            f"🕐 {datetime.now().strftime('%d.%m.%Y %H:%M')}",
            chat_id=message.chat.id,
            message_id=status_msg.message_id,
            parse_mode='HTML'
        )
        logger.info(f"DB updated, new: {new_count}")

    except Exception as e:
        logger.error(f"Update error: {e}")
        bot.edit_message_text(
            f"❌ Ошибка: {str(e)}",
            chat_id=message.chat.id,
            message_id=status_msg.message_id
        )

@bot.message_handler(func=lambda message: True, content_types=['text'])
def handle_text(message):
    query = message.text.strip()

    if query.startswith('/'):
        return

    if is_technique_id(query):
        tech_id = format_technique_id(query)
        tech = db.get_technique(tech_id)

        if tech:
            rus_name = db.get_russian_name(tech['id'])
            display_name = rus_name if rus_name else tech['name']
            tactic_rus = db.get_russian_tactic(tech.get('tactic_name', ''))
            pt_url = get_pt_url(tech['id'])

            response = messages.TECHNIQUE_TEMPLATE.format(
                id=tech['id'],
                name=display_name,
                tactic_name=tactic_rus,
                platform=tech.get('platform', 'Не указано'),
                description=format_description(tech.get('description', ''), 300),
                url=pt_url
            )

            malware_list = db.get_malware_by_technique(tech_id)
            if malware_list:
                response += f"\n\n🦠 <b>Используется в малварях:</b>\n"
                for malware in malware_list[:5]:
                    response += f"  • {malware}\n"

            bot.send_message(message.chat.id, response, parse_mode='HTML', disable_web_page_preview=True)
            return

    results = db.search_techniques(query)

    if not results:
        bot.send_message(
            message.chat.id,
            f"🔍 По запросу '{query}' ничего не найдено.\n\n"
            f"💡 Попробуйте:\n"
            f"• Поискать на русском (например, 'фишинг')\n"
            f"• Поискать на английском (например, 'phishing')\n"
            f"• Использовать ID (T1059)\n"
            f"• /tactics для списка тактик"
        )
        return

    response = f"🔍 <b>Результаты по '{query}':</b>\n\n"
    for tech in results:
        rus_name = db.get_russian_name(tech['id'])
        display_name = rus_name if rus_name else tech['name']
        tactic_rus = db.get_russian_tactic(tech['tactic_name'])
        pt_url = get_pt_url(tech['id'])

        response += f"<b>{tech['id']}</b> - {display_name}\n"
        response += f"📋 {tactic_rus}\n"
        response += f"📝 {format_description(tech.get('description', ''), 100)}\n"
        response += f"🔗 {pt_url}\n\n"

    if len(results) > 0:
        response += f"💡 Для деталей отправьте ID техники (например, {results[0]['id']})"

    bot.send_message(
        message.chat.id,
        response,
        parse_mode='HTML',
        disable_web_page_preview=True
    )

def background_update():
    while True:
        time.sleep(Config.UPDATE_INTERVAL)
        try:
            logger.info("🔄 Фоновое обновление...")
            stix_data = mitre.fetch_attack_data()
            if stix_data:
                parsed_data = mitre.parse_stix_data(stix_data)
                db.save_tactics(parsed_data['tactics'])
                new_count = 0
                for tech in parsed_data['techniques']:
                    existing = db.get_technique(tech['id'])
                    if not existing:
                        new_count += 1
                    db.save_technique(tech)
                if new_count > 0:
                    db.log_update(new_count, 0)
                    logger.info(f"✅ Добавлено {new_count} новых техник")
        except Exception as e:
            logger.error(f"Фоновое обновление: {e}")

if __name__ == '__main__':
    if not db.get_last_update_date():
        logger.info("📦 Первичная загрузка данных...")
        stix_data = mitre.fetch_attack_data()
        if stix_data:
            parsed_data = mitre.parse_stix_data(stix_data)
            db.save_tactics(parsed_data['tactics'])
            for tech in parsed_data['techniques']:
                db.save_technique(tech)
            db.log_update(len(parsed_data['techniques']), 0)
            logger.info(f"✅ Загружено {len(parsed_data['techniques'])} техник")

    thread = threading.Thread(target=background_update, daemon=True)
    thread.start()
    logger.info("🔄 Фоновое обновление запущено")

    logger.info("🚀 Бот запущен и готов к работе!")
    logger.info("=" * 50)

    try:
        bot.infinity_polling()
    except Exception as e:
        logger.error(f"❌ Критическая ошибка: {e}")
        sys.exit(1)
