import logging
import random
import os
import asyncio
from datetime import datetime, timedelta
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application,
    CommandHandler,
    CallbackQueryHandler,
    ContextTypes,
    MessageHandler,
    filters
)

# Configuración básica
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

TOKEN = os.getenv('TELEGRAM_TOKEN', '8303269115:AAERcGRQvKFj10wRgUh5dsa5xzTAB2iZbDw')

# Datos mejorados para México y EE.UU.
COUNTRIES = {
    "USA": {
        "cities": ["New York", "Los Angeles", "Chicago", "Houston", "Phoenix"],
        "banks": ["JPMorgan Chase", "Bank of America", "Wells Fargo", "Citibank"],
        "card_types": {
            "Visa": ["4539", "4556", "4916", "4532", "4929"],
            "Mastercard": ["2221", "2330", "5100", "5555", "5199"],
            "Amex": ["3700", "3723"]
        },
        "area_codes": {
            "New York": ["212", "718", "917"],
            "Los Angeles": ["213", "310", "323"],
            "Chicago": ["312", "773", "872"]
        }
    },
    "México": {
        "cities": ["Ciudad de México", "Guadalajara", "Monterrey", "Puebla", "Tijuana"],
        "banks": ["BBVA", "Banamex", "Santander", "HSBC México", "Banorte"],
        "card_types": {
            "Visa": ["4169", "4024", "4485", "4716"],
            "Mastercard": ["5100", "5555", "5199", "5300"],
            "Amex": ["3700", "3723"]
        },
        "area_codes": {
            "Ciudad de México": ["55"],
            "Guadalajara": ["33"],
            "Monterrey": ["81"]
        }
    }
}

# Direcciones realistas por ciudad
ADDRESSES = {
    "Ciudad de México": {
        "streets": ["Paseo de la Reforma", "Avenida Insurgentes", "Calzada de Tlalpan", 
                   "Avenida Chapultepec", "Calle Madero"],
        "colonies": ["Polanco", "Roma", "Condesa", "Del Valle", "Nápoles"],
        "zips": ["06500", "06600", "06700", "06800", "06900"]
    },
    "Monterrey": {
        "streets": ["Avenida Constitución", "Avenida Garza Sada", "Avenida Morones Prieto"],
        "colonies": ["San Pedro", "Contry", "Del Valle"],
        "zips": ["64000", "64100", "64200"]
    },
    "New York": {
        "streets": ["Broadway", "5th Ave", "Wall St", "Lexington Ave"],
        "neighborhoods": ["Manhattan", "Brooklyn", "Queens"],
        "zips": ["10001", "10002", "10003"]
    }
}

# Tiempos de espera realistas
WAIT_TIMES = {
    'scan': [5, 10],
    'extract': [8, 15],
    'attack': [6, 12]
}

def random_wait(action):
    return random.uniform(*WAIT_TIMES[action])

def generate_realistic_name(country):
    """Genera nombres realistas con combinaciones probables"""
    if country == "México":
        first_names = {
            "male": ["Juan", "José", "Carlos", "Luis", "Miguel", "Jesús", "Manuel", "Pedro"],
            "female": ["María", "Guadalupe", "Ana", "Patricia", "Verónica", "Laura", "Sofía", "Teresa"]
        }
        last_names = [
            "Hernández", "García", "Martínez", "López", "González", 
            "Pérez", "Rodríguez", "Sánchez", "Ramírez", "Flores"
        ]
    else:  # USA
        first_names = {
            "male": ["James", "John", "Robert", "Michael", "William", "David", "Richard", "Joseph"],
            "female": ["Mary", "Jennifer", "Lisa", "Susan", "Margaret", "Dorothy", "Sarah", "Jessica"]
        }
        last_names = [
            "Smith", "Johnson", "Williams", "Brown", "Jones", 
            "Miller", "Davis", "Garcia", "Rodriguez", "Wilson"
        ]
    
    gender = random.choice(["male", "female"])
    first_name = random.choice(first_names[gender])
    
    # Segundo nombre común en México
    if country == "México" and random.random() > 0.7:
        second_name = random.choice(first_names[gender])
        first_name = f"{first_name} {second_name}"
    
    # Apellidos compuestos
    if country == "México" and random.random() > 0.5:
        last_name = f"{random.choice(last_names)} {random.choice(last_names)}"
    else:
        last_name = random.choice(last_names)
    
    return f"{first_name} {last_name}"

def generate_realistic_address(country, city=None):
    if not city:
        city = random.choice(COUNTRIES[country]["cities"])
    
    if city in ADDRESSES:
        data = ADDRESSES[city]
        street = random.choice(data["streets"])
        number = random.randint(100, 999)
        
        if country == "México":
            colony = random.choice(data["colonies"])
            zip_code = random.choice(data["zips"])
            return f"{street} {number}, Col. {colony}, {zip_code}, {city}, {country}"
        else:  # USA
            neighborhood = random.choice(data["neighborhoods"])
            zip_code = random.choice(data["zips"])
            return f"{number} {street}, {neighborhood}, {city} {zip_code}, USA"
    else:
        return f"Calle {random.randint(1, 200)}, Col. Centro, {city}, {country}"

def generate_phone(country, city):
    if country == "México":
        area_code = random.choice(COUNTRIES[country]["area_codes"].get(city, ["55"]))
        return f"+52 {area_code} {random.randint(1000, 9999)} {random.randint(1000, 9999)}"
    else:  # USA
        area_code = random.choice(COUNTRIES[country]["area_codes"].get(city, ["212"]))
        return f"+1 ({area_code}) {random.randint(100, 999)}-{random.randint(1000, 9999)}"

def generate_email(name):
    return name.lower().replace(" ", ".") + random.choice(["@gmail.com", "@hotmail.com", "@outlook.com"])

def generate_cc(country):
    bank = random.choice(COUNTRIES[country]["banks"])
    card_type = random.choice(list(COUNTRIES[country]["card_types"].keys()))
    prefix = random.choice(COUNTRIES[country]["card_types"][card_type])
    
    # Generar número válido con algoritmo Luhn
    cc_number = prefix + ''.join([str(random.randint(0, 9)) for _ in range(15 - len(prefix))])
    
    total = 0
    for i, digit in enumerate(cc_number):
        num = int(digit)
        if i % 2 == 0:
            num *= 2
            if num > 9:
                num -= 9
        total += num
    
    check_digit = (10 - (total % 10)) % 10
    return {
        "number": cc_number + str(check_digit),
        "type": card_type,
        "bank": bank,
        "limit": random.choice(["$2,000", "$5,000", "$10,000", "$15,000"])
    }

def generate_cc_full(country=None):
    if not country:
        country = random.choice(list(COUNTRIES.keys()))
    
    city = random.choice(COUNTRIES[country]["cities"])
    full_name = generate_realistic_name(country)
    address = generate_realistic_address(country, city)
    cc_data = generate_cc(country)
    
    exp_month = random.randint(1, 12)
    exp_year = datetime.now().year + random.randint(1, 5)
    cvv = f"{random.randint(0, 999):03d}"
    phone = generate_phone(country, city)
    email = generate_email(full_name)
    issue_date = (datetime.now() - timedelta(days=random.randint(30, 365))).strftime("%Y-%m-%d")
    
    return (
        f"💳 *{cc_data['type']} {cc_data['bank']}* ({country})\n"
        f"🔢 *Número:* `{cc_data['number'][:4]} {cc_data['number'][4:8]} {cc_data['number'][8:12]} {cc_data['number'][12:]}`\n"
        f"📅 *Vence:* {exp_month:02d}/{exp_year}  🆔 *CVV:* {cvv}\n"
        f"💲 *Límite:* {cc_data['limit']}  📅 *Emisión:* {issue_date}\n"
        f"👤 *Titular:* {full_name}\n"
        f"🏠 *Dirección:* {address}\n"
        f"📧 *Email:* {email}\n"
        f"📞 *Teléfono:* {phone}\n"
        f"🔐 *Clave Bancaria:* {random.randint(1000, 9999)}"
    )

async def simulate_db_scan():
    await asyncio.sleep(random_wait('scan'))
    
    db_types = ["MySQL", "PostgreSQL", "MongoDB", "SQLite", "Oracle", "SQL Server"]
    vuln_types = ["SQL Injection", "XSS", "IDOR", "Broken Auth", "SSRF", "XXE"]
    
    results = []
    for _ in range(random.randint(3, 6)):
        db_type = random.choice(db_types)
        vuln = random.choice(vuln_types)
        records = random.randint(500, 10000)
        date = (datetime.now() - timedelta(days=random.randint(0, 30))).strftime("%Y-%m-%d %H:%M:%S")
        ip = f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,255)}"
        port = random.choice([3306, 5432, 27017, 1433, 1521])
        
        results.append(
            f"🔍 *Base de datos encontrada* 🔍\n"
            f"🏦 Tipo: {db_type}\n"
            f"📊 Registros: {records:,}\n"
            f"🛡️ Vulnerabilidad: {vuln}\n"
            f"🌐 IP: {ip}:{port}\n"
            f"📅 Última actualización: {date}\n"
            f"🔑 Credenciales: admin:{random.randint(1000,9999)}\n"
        )
    
    return "\n".join(results)

async def simulate_data_extraction(country=None):
    await asyncio.sleep(random_wait('extract'))
    num_records = random.randint(3, 5)  # Menos registros pero más detallados
    return [generate_cc_full(country) for _ in range(num_records)]

async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = await update.message.reply_text(
        "🕵️‍♂️ *Iniciando escaneo avanzado...*\n\n"
        "🔍 Analizando redes... 10%\n"
        "🌐 Identificando servicios... 25%\n"
        "🛡️ Evaluando configuraciones... 40%",
        parse_mode='Markdown'
    )
    
    for progress in [55, 70, 85, 100]:
        await asyncio.sleep(random.uniform(1.5, 3))
        await msg.edit_text(
            f"🕵️‍♂️ *Escaneo en progreso...*\n\n"
            f"🔍 Analizando redes... {progress}%\n"
            f"🌐 Identificando servicios... {min(progress+15, 100)}%\n"
            f"🛡️ Evaluando configuraciones... {min(progress+30, 100)}%",
            parse_mode='Markdown'
        )
    
    scan_results = await simulate_db_scan()
    await context.bot.send_message(
        update.effective_chat.id,
        f"✅ *Escaneo completado* ✅\n\n{scan_results}\n"
        f"Usa /extract para obtener datos",
        parse_mode='Markdown'
    )

async def extract(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🇺🇸 EE.UU.", callback_data='extract_USA'),
         InlineKeyboardButton("🇲🇽 México", callback_data='extract_MEX')],
        [InlineKeyboardButton("🌍 Aleatorio", callback_data='extract_random')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "🌎 *Seleccione el país de origen:*",
        parse_mode='Markdown',
        reply_markup=reply_markup
    )

async def perform_extract(update: Update, context: ContextTypes.DEFAULT_TYPE, country_code=None):
    query = update.callback_query
    await query.answer()
    
    country_map = {
        'USA': 'USA',
        'MEX': 'México',
        'random': None
    }
    country = country_map.get(country_code)
    country_display = "Aleatorio" if country is None else "EE.UU." if country == "USA" else "México"
    
    await query.edit_message_text(
        f"🌍 *País seleccionado:* {country_display}\n"
        "💾 *Conectando a base de datos...*",
        parse_mode='Markdown'
    )
    
    for progress in [25, 50, 75, 100]:
        await asyncio.sleep(random.uniform(1, 2))
        await query.edit_message_text(
            f"🌍 *País seleccionado:* {country_display}\n"
            f"💾 *Extrayendo datos...* {progress}%",
            parse_mode='Markdown'
        )
    
    data_list = await simulate_data_extraction(country)
    for data in data_list:
        await context.bot.send_message(
            chat_id=update.effective_chat.id,
            text=data,
            parse_mode='Markdown'
        )
        await asyncio.sleep(1)  # Pequeña pausa entre tarjetas

async def attack(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = await update.message.reply_text(
        "💣 *Preparando ataque...*\n\n"
        "🧪 Cargando vectores... 30%\n"
        "🛠️ Configurando payloads... 50%\n"
        "🚀 Preparando inyección... 70%",
        parse_mode='Markdown'
    )
    
    for progress in [80, 90, 100]:
        await asyncio.sleep(random.uniform(1, 2.5))
        await msg.edit_text(
            f"💣 *Ataque en progreso...*\n\n"
            f"🧪 Cargando vectores... {progress}%\n"
            f"🛠️ Configurando payloads... {min(progress+10, 100)}%\n"
            f"🚀 Preparando inyección... {min(progress+20, 100)}%",
            parse_mode='Markdown'
        )
    
    vulns = ["SQLi exitosa", "XSS almacenado", "Credenciales expuestas", "CSRF posible", "RCE conseguido"]
    exploit = random.choice([
        "DROP TABLE users;--",
        "<?php system($_GET['cmd']); ?>",
        "admin' OR '1'='1'--",
        "../../../../etc/passwd"
    ])
    await context.bot.send_message(
        update.effective_chat.id,
        f"🔥 *Ataque completado* 🔥\n\n"
        f"🎯 Vulnerabilidad: {random.choice(vulns)}\n"
        f"💥 Exploit usado: `{exploit}`\n"
        f"📌 Severidad: Alta\n\n"
        f"Puedes extraer datos con /extract",
        parse_mode='Markdown'
    )

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    keyboard = [
        [InlineKeyboardButton("🔍 ESCANEAR", callback_data='scan'),
         InlineKeyboardButton("💳 EXTRAER", callback_data='extract')],
        [InlineKeyboardButton("⚔️ ATACAR", callback_data='attack'),
         InlineKeyboardButton("ℹ️ AYUDA", callback_data='help')]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    await update.message.reply_text(
        "👑 *BOT ÉLITE - SISTEMA PROFESIONAL* 👑\n\n"
        "Seleccione una operación:",
        parse_mode='Markdown',
        reply_markup=reply_markup
    )

async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    
    if query.data == 'scan':
        await scan(query.message, context)
    elif query.data == 'extract':
        await extract(query.message, context)
    elif query.data == 'attack':
        await attack(query.message, context)
    elif query.data == 'help':
        await help_command(query.message, context)
    elif query.data.startswith('extract_'):
        country_code = query.data.split('_')[1]
        await perform_extract(update, context, country_code)

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👑 *BOT ÉLITE - AYUDA* 👑\n\n"
        "🔹 *Comandos disponibles:*\n"
        "/start - Menú principal\n"
        "/scan - Escanear objetivos\n"
        "/extract - Extraer datos\n"
        "/attack - Pruebas de vulnerabilidad\n\n"
        "🔹 *Características:*\n"
        "- Generación de datos ultra-realistas\n"
        "- Tarjetas válidas con algoritmo Luhn\n"
        "- Soporte para México y EE.UU.\n"
        "- Información completa de tarjetas",
        parse_mode='Markdown'
    )

async def unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "⚠️ Comando no reconocido. Use /help para ver opciones disponibles."
    )

# Sistema keep-alive para Replit
from flask import Flask
from threading import Thread

app = Flask(__name__)

@app.route('/')
def home():
    return "Sistema operativo"

def run():
    app.run(host='0.0.0.0', port=8080)

def keep_alive():
    server = Thread(target=run)
    server.start()

def main():
    keep_alive()
    
    application = Application.builder().token(TOKEN).build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("scan", scan))
    application.add_handler(CommandHandler("extract", extract))
    application.add_handler(CommandHandler("attack", attack))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CallbackQueryHandler(button_handler))

    application.add_handler(MessageHandler(filters.COMMAND & ~filters.Regex(r'^(start|scan|extract|attack|help)$'), unknown))

    logger.info("Bot Élite iniciado: Sistema operativo")
    application.run_polling()

if __name__ == '__main__':
    main()