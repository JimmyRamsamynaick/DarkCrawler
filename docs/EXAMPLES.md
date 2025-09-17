# 📚 Exemples d'Utilisation DarkCrawler

Ce document contient des exemples pratiques d'utilisation de DarkCrawler pour différents cas d'usage.

## 🚀 Démarrage Rapide

### Exemple 1: Scan Basique
```bash
# Scanner avec la configuration par défaut
python main.py --config config/keywords.json --output reports/

# Résultat attendu:
# ✅ Tor connection established
# 🔍 Scanning 5 URLs...
# 📊 Found 12 potential leaks
# 📄 Reports generated in reports/
```

### Exemple 2: Test de Démonstration
```bash
# Lancer le test avec des données simulées
python test_demo.py

# Sortie exemple:
# 🕸️ DarkCrawler - Test de Démonstration
# ================================
# 
# 🔍 Détections trouvées:
# - Email: admin@company.com (position: 156)
# - Password: secret123 (position: 289)
# - Phone: +1-555-0123 (position: 445)
# 
# 📊 Statistiques:
# - Total détections: 6
# - Emails: 2
# - Mots de passe: 2
# - Téléphones: 2
```

## 🌐 Interface Web

### Exemple 3: Démarrer l'Interface Web
```bash
# Lancer l'interface web
python web_interface.py

# Sortie:
# 🌐 DarkCrawler Web Interface
# ============================
# * Running on http://localhost:5001
# * Debug mode: on
# * Restarting with stat
```

### Exemple 4: Utilisation de l'Interface Web
1. **Ouvrir le navigateur** : http://localhost:5001
2. **Dashboard** : Voir les statistiques en temps réel
3. **Lancer un scan** : Cliquer sur "Nouveau Scan"
4. **Télécharger rapports** : Section "Rapports" → "Télécharger"

## 🔧 Utilisation Programmatique

### Exemple 5: Scanner une URL Spécifique
```python
from crawler.detector import DataLeakDetector
import json

# Initialiser le détecteur
detector = DataLeakDetector()

# Scanner une URL
url = "http://example.onion"
results = detector.scan_url(url)

# Afficher les résultats
print(f"🔍 Scan de {url}")
print(f"📊 {len(results)} fuites détectées:")

for leak in results:
    print(f"  - {leak.leak_type}: {leak.content}")
    print(f"    Position: {leak.position}")
    print(f"    Contexte: {leak.context[:50]}...")
    print()
```

### Exemple 6: Scanner Plusieurs URLs
```python
from crawler.detector import DataLeakDetector

detector = DataLeakDetector()

urls = [
    "http://site1.onion",
    "http://site2.onion", 
    "http://site3.onion"
]

all_results = []
for url in urls:
    print(f"🔍 Scanning {url}...")
    results = detector.scan_url(url)
    all_results.extend(results)
    print(f"  ✅ {len(results)} leaks found")

print(f"\n📊 Total: {len(all_results)} leaks across all sites")
```

### Exemple 7: Détection Personnalisée
```python
from crawler.detector import DataLeakDetector
import re

class CustomDetector(DataLeakDetector):
    def __init__(self):
        super().__init__()
        # Ajouter des patterns personnalisés
        self.patterns.update({
            'social_security': r'\b\d{3}-\d{2}-\d{4}\b',
            'bitcoin_address': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'api_key': r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?'
        })

# Utiliser le détecteur personnalisé
detector = CustomDetector()
content = """
Contact: john.doe@company.com
SSN: 123-45-6789
Bitcoin: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
API Key: api_key = "sk_live_abcdef123456789"
"""

leaks = detector.detect_leaks(content)
for leak in leaks:
    print(f"{leak.leak_type}: {leak.content}")
```

## 🔔 Notifications

### Exemple 8: Configuration Slack
```python
from notifications.realtime import NotificationManager

# Configurer Slack
manager = NotificationManager()
manager.configure_slack('https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX')

# Envoyer une notification
manager.send_notification(
    message="🚨 Fuite critique détectée: 15 emails exposés",
    priority="high",
    channels=["slack"]
)

# Notification avec détails
leak_details = {
    'type': 'email',
    'count': 15,
    'url': 'http://example.onion',
    'timestamp': '2024-01-17T14:30:22Z'
}

manager.send_notification(
    message=f"🔍 Détection: {leak_details['count']} {leak_details['type']}s trouvés",
    priority="medium",
    channels=["slack"],
    metadata=leak_details
)
```

### Exemple 9: Configuration Email
```python
from notifications.realtime import NotificationManager

manager = NotificationManager()

# Configuration Gmail
manager.configure_email(
    smtp_server='smtp.gmail.com',
    smtp_port=587,
    username='your-email@gmail.com',
    password='your-app-password'  # Utiliser un mot de passe d'application
)

# Envoyer un rapport par email
manager.send_notification(
    message="Rapport de scan DarkCrawler",
    priority="low",
    channels=["email"],
    metadata={
        'subject': 'Rapport DarkCrawler - 17/01/2024',
        'recipients': ['security@company.com', 'admin@company.com']
    }
)
```

### Exemple 10: Notifications Multi-Canaux
```python
from notifications.realtime import NotificationManager
from crawler.detector import DataLeakDetector

# Configuration complète
manager = NotificationManager()
manager.configure_slack('https://hooks.slack.com/services/...')
manager.configure_email('smtp.gmail.com', 587, 'user@gmail.com', 'password')
manager.configure_discord('https://discord.com/api/webhooks/...')

# Scanner avec notifications automatiques
detector = DataLeakDetector()
results = detector.scan_url('http://example.onion')

# Notifications basées sur la gravité
for leak in results:
    if leak.leak_type in ['password', 'credit_card']:
        # Critique: tous les canaux
        manager.send_notification(
            message=f"🚨 CRITIQUE: {leak.leak_type} détecté",
            priority="critical",
            channels=["slack", "email", "discord"]
        )
    elif leak.leak_type == 'email':
        # Moyen: Slack seulement
        manager.send_notification(
            message=f"⚠️ Email détecté: {leak.content}",
            priority="medium", 
            channels=["slack"]
        )
```

## 📊 Génération de Rapports

### Exemple 11: Rapport JSON Personnalisé
```python
from reports.generator import ReportGenerator
from datetime import datetime
import json

generator = ReportGenerator()

# Données de scan simulées
scan_data = {
    'scan_id': f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
    'timestamp': datetime.now().isoformat(),
    'leaks': [
        {
            'leak_type': 'email',
            'content': 'admin@company.com',
            'position': 245,
            'context': 'Contact admin@company.com for support',
            'url': 'http://example.onion'
        }
    ]
}

# Générer rapport JSON
json_report = generator.generate_json_report(scan_data['leaks'])
print("📄 Rapport JSON généré:")
print(json.dumps(json_report, indent=2, ensure_ascii=False))
```

### Exemple 12: Rapport Markdown avec Graphiques
```python
from reports.generator import ReportGenerator

generator = ReportGenerator()

# Générer rapport Markdown
leaks = [
    {'leak_type': 'email', 'content': 'user1@test.com', 'position': 100},
    {'leak_type': 'email', 'content': 'user2@test.com', 'position': 200},
    {'leak_type': 'password', 'content': 'secret123', 'position': 300},
]

markdown_report = generator.generate_markdown_report(leaks)

# Sauvegarder le rapport
with open('reports/custom_report.md', 'w', encoding='utf-8') as f:
    f.write(markdown_report)

print("📄 Rapport Markdown sauvegardé: reports/custom_report.md")
```

## 🔧 Configuration Avancée

### Exemple 13: Configuration Personnalisée
```python
import json
from pathlib import Path

# Configuration personnalisée
custom_config = {
    "tor": {
        "proxy_host": "127.0.0.1",
        "proxy_port": 9050,
        "timeout": 45,
        "max_retries": 3
    },
    "crawler": {
        "max_depth": 3,
        "delay": 2,
        "user_agent": "DarkCrawler/1.0",
        "max_threads": 5,
        "respect_robots": True
    },
    "detection": {
        "patterns": {
            "email": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "phone": r"\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}",
            "ssn": r"\b\d{3}-\d{2}-\d{4}\b",
            "credit_card": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b"
        },
        "min_confidence": 0.8
    },
    "alerts": {
        "email": {
            "enabled": True,
            "smtp_server": "smtp.company.com",
            "smtp_port": 587,
            "use_tls": True
        },
        "webhook": {
            "enabled": True,
            "slack_url": "https://hooks.slack.com/...",
            "discord_url": "https://discord.com/api/webhooks/..."
        }
    }
}

# Sauvegarder la configuration
config_path = Path('config/custom_config.json')
with open(config_path, 'w') as f:
    json.dump(custom_config, f, indent=2)

print(f"⚙️ Configuration sauvegardée: {config_path}")
```

### Exemple 14: Utiliser la Configuration Personnalisée
```bash
# Utiliser la configuration personnalisée
python main.py --config config/custom_config.json --output reports/custom/

# Avec options supplémentaires
python main.py \
  --config config/custom_config.json \
  --output reports/custom/ \
  --verbose \
  --max-depth 4 \
  --timeout 60
```

## 🧪 Tests et Débogage

### Exemple 15: Test Unitaire Personnalisé
```python
import unittest
from crawler.detector import DataLeakDetector

class TestCustomDetection(unittest.TestCase):
    def setUp(self):
        self.detector = DataLeakDetector()
    
    def test_email_detection(self):
        content = "Contact us at support@company.com for help"
        leaks = self.detector.detect_leaks(content)
        
        email_leaks = [l for l in leaks if l.leak_type == 'email']
        self.assertEqual(len(email_leaks), 1)
        self.assertEqual(email_leaks[0].content, 'support@company.com')
    
    def test_multiple_patterns(self):
        content = """
        Email: admin@test.com
        Phone: +1-555-0123
        Password: secret123
        """
        leaks = self.detector.detect_leaks(content)
        
        leak_types = [l.leak_type for l in leaks]
        self.assertIn('email', leak_types)
        self.assertIn('phone', leak_types)
        self.assertIn('password', leak_types)

if __name__ == '__main__':
    unittest.main()
```

### Exemple 16: Débogage avec Logs Détaillés
```python
import logging
from crawler.detector import DataLeakDetector

# Configuration des logs détaillés
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('debug.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('DarkCrawler')

# Scanner avec logs détaillés
detector = DataLeakDetector()
logger.info("🔍 Démarrage du scan de débogage")

try:
    results = detector.scan_url('http://example.onion')
    logger.info(f"✅ Scan terminé: {len(results)} fuites détectées")
    
    for i, leak in enumerate(results):
        logger.debug(f"Fuite {i+1}: {leak.leak_type} = {leak.content}")
        
except Exception as e:
    logger.error(f"❌ Erreur lors du scan: {e}")
    logger.exception("Détails de l'erreur:")
```

## 🚀 Cas d'Usage Avancés

### Exemple 17: Monitoring Continu
```python
import time
import schedule
from crawler.detector import DataLeakDetector
from notifications.realtime import NotificationManager

def scheduled_scan():
    """Scan programmé toutes les heures"""
    detector = DataLeakDetector()
    manager = NotificationManager()
    
    urls_to_monitor = [
        'http://site1.onion',
        'http://site2.onion'
    ]
    
    total_leaks = 0
    for url in urls_to_monitor:
        try:
            results = detector.scan_url(url)
            total_leaks += len(results)
            
            if results:
                manager.send_notification(
                    message=f"🔍 {len(results)} nouvelles fuites sur {url}",
                    priority="medium",
                    channels=["slack"]
                )
        except Exception as e:
            manager.send_notification(
                message=f"❌ Erreur scan {url}: {e}",
                priority="high",
                channels=["email"]
            )
    
    print(f"📊 Scan programmé terminé: {total_leaks} fuites au total")

# Programmer les scans
schedule.every().hour.do(scheduled_scan)
schedule.every().day.at("09:00").do(scheduled_scan)

print("⏰ Monitoring continu démarré...")
while True:
    schedule.run_pending()
    time.sleep(60)
```

### Exemple 18: Intégration avec Base de Données
```python
import sqlite3
from datetime import datetime
from crawler.detector import DataLeakDetector

class DatabaseLogger:
    def __init__(self, db_path='darkcrawler.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                url TEXT,
                total_leaks INTEGER
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS leaks (
                id INTEGER PRIMARY KEY,
                scan_id INTEGER,
                leak_type TEXT,
                content TEXT,
                position INTEGER,
                context TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans (id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def log_scan(self, url, leaks):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Insérer le scan
        cursor.execute(
            'INSERT INTO scans (timestamp, url, total_leaks) VALUES (?, ?, ?)',
            (datetime.now().isoformat(), url, len(leaks))
        )
        scan_id = cursor.lastrowid
        
        # Insérer les fuites
        for leak in leaks:
            cursor.execute(
                'INSERT INTO leaks (scan_id, leak_type, content, position, context) VALUES (?, ?, ?, ?, ?)',
                (scan_id, leak.leak_type, leak.content, leak.position, leak.context)
            )
        
        conn.commit()
        conn.close()
        return scan_id

# Utilisation
detector = DataLeakDetector()
db_logger = DatabaseLogger()

url = 'http://example.onion'
results = detector.scan_url(url)
scan_id = db_logger.log_scan(url, results)

print(f"📊 Scan {scan_id} enregistré: {len(results)} fuites")
```

Ces exemples couvrent les principaux cas d'usage de DarkCrawler, de l'utilisation basique aux intégrations avancées. Chaque exemple peut être adapté selon vos besoins spécifiques.