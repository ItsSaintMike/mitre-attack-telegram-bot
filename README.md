# 🤖 MITRE ATT&CK Telegram Bot

Telegram-бот для малварь-аналитиков, пентестеров и специалистов по кибербезопасности. Предоставляет быстрый доступ к базе знаний MITRE ATT&CK с полным переводом на русский язык.

## ✨ Возможности

- 🔍 **Умный поиск** — ищите техники по ID (T1059), названию или описанию на русском и английском
- 🇷🇺 **Полный русский перевод** — все тактики и техники переведены на русский язык
- 🆕 **Отслеживание новых техник** — узнавайте о свежих добавлениях в MITRE ATT&CK
- 🦠 **Анализ малвари** — сопоставляйте вредоносное ПО с используемыми техниками
- 📊 **Цепочка атак** — визуализируйте поведение малвари по тактикам (Attack Chain)
- 💡 **Подсказки для YARA** — получайте рекомендации по написанию YARA-правил
- 🔗 **Русские ссылки** — все ссылки ведут на русскую версию MITRE ATT&CK от Positive Technologies

## 📋 Команды бота

| Команда | Описание | Пример |
|---------|----------|--------|
| `/start` | Приветствие и главное меню | `/start` |
| `/help` | Справка по командам | `/help` |
| `/new` | Новые техники за последнюю неделю | `/new` |
| `/tactics` | Список всех тактик MITRE ATT&CK | `/tactics` |
| `/tactic` | Техники конкретной тактики | `/tactic Initial Access` |
| `/malware` | Анализ поведения малвари | `/malware Emotet` |
| `/add_malware` | Добавить малварь в базу | `/add_malware` |
| `/malware_list` | Список всех малварей в базе | `/malware_list` |
| `/update` | Принудительное обновление базы данных | `/update` |

**Поиск по тексту:** просто отправьте любой запрос — бот найдёт релевантные техники (например, `фишинг`, `powershell`, `T1059`).

## 🚀 Установка и запуск

### 1. Клонирование репозитория

```bash
git clone https://github.com/ItsSaintMike/mitre-attack-telegram-bot.git
cd mitre-attack-telegram-bot
```

### 2. Создание виртуального окружения


```bash
python3 -m venv venv
source venv/bin/activate  # Для Linux/Mac
# venv\Scripts\activate    # Для Windows
```

### 3. Установка зависимостей

```bash
pip install -r requirements.txt

Настройка переменных окружения
Создайте файл .env и добавьте в него токен вашего бота:
```
### 4. Настройка переменных окружения

```bash
nano .env


BOT_TOKEN=ваш_токен_от_BotFather
MITRE_API_URL=https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
MITRE_ATTACK_URL=https://mitre.ptsecurity.com/ru-RU
DB_PATH=data/mitre_data.db
UPDATE_INTERVAL=86400
MAX_SEARCH_RESULTS=15
LOG_LEVEL=INFO
```

### 5. Запуск бота

```bash
python bot.py
```

### 6. Запуск через PM2

```bash
pm2 start venv/bin/python --name "mitre-bot" -- bot.py
pm2 save
pm2 startup
```
### 📁 Структура проекта

mitre-attack-telegram-bot/
├── bot.py # Главный файл бота
├── config.py # Конфигурация и настройки
├── database.py # Работа с SQLite
├── mitre_api.py # API MITRE ATT&CK
├── utils.py # Вспомогательные функции
├── messages.py # Шаблоны сообщений
├── translations.csv # Полный русский перевод (700+ техник)
├── requirements.txt # Зависимости Python
├── .env # Переменные окружения (не в Git)
├── .gitignore # Исключения для Git
├── README.md # Документация
├── data/ # База данных SQLite (создаётся автоматически)
└── logs/ # Логи работы бота (создаётся автоматически)

### 🎯 Для кого этот бот
Малварь-аналитики — быстрый доступ к описаниям техник и их связи с вредоносным ПО
Специалисты SOC — оперативный поиск информации по инцидентам
Пентестеры — планирование атак на основе тактик MITRE ATT&CK
Исследователи — изучение поведения злоумышленников
Студенты — изучение фреймворка MITRE ATT&CK на практике

### 🛠️ Используемые технологии

Python 3.8+ — основной язык

pyTelegramBotAPI — работа с Telegram API

SQLite — локальная база данных

Requests — HTTP-запросы к API MITRE

BeautifulSoup4 — парсинг веб-страниц

PM2 — управление процессами в продакшене

### 📊 Данные

Источник: официальный STIX 2.1 API MITRE ATT&CK

Версия: ATT&CK v15.1 (Positive Technologies)

Тактик: 14 (обновляется до 15 в v19)

Техник: 202 основные + 435 подтехник = 637 техник

Перевод: полный русский перевод всех тактик и техник

### 🤝 Как внести вклад

1. Форкните репозиторий
2. Создайте ветку для новой функции (git checkout -b feature/amazing-feature)
3. Сделайте коммит изменений (git commit -m 'Add some amazing feature')
4. Запушьте ветку (git push origin feature/amazing-feature)
5. Откройте Pull Request

### 📝 Лицензия

Распространяется под лицензией MIT. Подробности в файле LICENSE.

### 📧 Контакты

Автор: ItsSaintMike
Репозиторий: https://github.com/ItsSaintMike/mitre-attack-telegram-bot

### ⭐ Если вам понравился проект
Поставьте звезду на GitHub — это поможет другим специалистам найти этот инструмент! ⭐

