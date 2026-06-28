#!/usr/bin/env python3
import os
import sys
import json
import requests
from database import Database
from mitre_api import MitreAPI

print("📦 Начинаю загрузку базы данных MITRE ATT&CK...")

# Инициализация
db = Database()
mitre = MitreAPI()

# Загружаем данные
print("📥 Загрузка данных из API...")
stix_data = mitre.fetch_attack_data()

if not stix_data:
    print("❌ Не удалось загрузить данные!")
    print("Проверьте интернет-соединение и URL в .env")
    sys.exit(1)

print(f"✅ Данные загружены. Размер: {len(str(stix_data))} байт")

# Парсим
print("🔄 Парсинг данных...")
parsed_data = mitre.parse_stix_data(stix_data)

print(f"📊 Найдено тактик: {len(parsed_data['tactics'])}")
print(f"📊 Найдено техник: {len(parsed_data['techniques'])}")

# Сохраняем тактики
print("💾 Сохранение тактик...")
db.save_tactics(parsed_data['tactics'])

# Сохраняем техники
print("💾 Сохранение техник...")
for tech in parsed_data['techniques']:
    db.save_technique(tech)

# Логируем обновление
db.log_update(len(parsed_data['techniques']), 0)

print("✅ База данных успешно загружена!")
print(f"📊 Всего техник: {len(parsed_data['techniques'])}")
print(f"📋 Всего тактик: {len(parsed_data['tactics'])}")
print("🚀 Теперь можно запускать бота: python bot.py")
