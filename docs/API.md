# 📚 Documentation API DarkCrawler

Cette documentation détaille toutes les classes, méthodes et fonctions disponibles dans DarkCrawler.

## 🏗️ Architecture

```
DarkCrawler/
├── crawler/
│   ├── detector.py      # DataLeakDetector
│   ├── parser.py        # HTMLParser
│   └── tor_session.py   # TorSession
├── reports/
│   ├── generator.py     # ReportGenerator
│   └── exporter.py      # ReportExporter
├── notifications/
│   └── realtime.py      # NotificationManager
└── alerts/
    ├── logger.py        # AlertLogger
    ├── email.py         # EmailAlert
    └── webhook.py       # WebhookAlert
```

## 🔍 Module `crawler.detector`

### Classe `DataLeakDetector`

Classe principale pour la détection de fuites de données.

#### Constructeur
```python
DataLeakDetector(config_path: str = None)
```

**Paramètres:**
- `config_path` (str, optionnel): Chemin vers le fichier de configuration

**Exemple:**
```python
from crawler.detector import DataLeakDetector

# Avec configuration par défaut
detector = DataLeakDetector()

# Avec configuration personnalisée
detector = DataLeakDetector('config/custom_config.json')
```

#### Méthodes

##### `scan_url(url: str) -> List[LeakDetection]`

Scanne une URL spécifique pour détecter des fuites.

**Paramètres:**
- `url` (str): URL à scanner (format .onion)

**Retour:**
- `List[LeakDetection]`: Liste des fuites détectées

**Exceptions:**
- `ConnectionError`: Problème de connexion Tor
- `TimeoutError`: Timeout de la requête
- `ValueError`: URL invalide

**Exemple:**
```python
detector = DataLeakDetector()
results = detector.scan_url('http://example.onion')

for leak in results:
    print(f"Type: {leak.leak_type}")
    print(f"Contenu: {leak.content}")
    print(f"Position: {leak.position}")
```

##### `scan_multiple(urls: List[str]) -> Dict[str, List[LeakDetection]]`

Scanne plusieurs URLs en parallèle.

**Paramètres:**
- `urls` (List[str]): Liste des URLs à scanner

**Retour:**
- `Dict[str, List[LeakDetection]]`: Dictionnaire {url: [fuites]}

**Exemple:**
```python
urls = ['http://site1.onion', 'http://site2.onion']
results = detector.scan_multiple(urls)

for url, leaks in results.items():
    print(f"{url}: {len(leaks)} fuites")
```

##### `detect_leaks(content: str, url: str = None) -> List[LeakDetection]`

Détecte des fuites dans du contenu texte.

**Paramètres:**
- `content` (str): Contenu à analyser
- `url` (str, optionnel): URL source du contenu

**Retour:**
- `List[LeakDetection]`: Liste des fuites détectées

**Exemple:**
```python
content = "Contact: admin@company.com, Password: secret123"
leaks = detector.detect_leaks(content)
```

##### `add_custom_pattern(name: str, pattern: str, severity: str = 'medium')`

Ajoute un pattern de détection personnalisé.

**Paramètres:**
- `name` (str): Nom du pattern
- `pattern` (str): Expression régulière
- `severity` (str): Niveau de gravité ('low', 'medium', 'high', 'critical')

**Exemple:**
```python
detector.add_custom_pattern(
    'bitcoin_address',
    r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
    'high'
)
```

### Classe `LeakDetection`

Représente une fuite détectée.

#### Attributs
- `leak_type` (str): Type de fuite (email, password, phone, etc.)
- `content` (str): Contenu de la fuite
- `position` (int): Position dans le texte
- `context` (str): Contexte autour de la fuite
- `url` (str): URL source
- `severity` (str): Niveau de gravité
- `timestamp` (datetime): Moment de la détection

#### Méthodes

##### `to_dict() -> dict`

Convertit l'objet en dictionnaire.

**Exemple:**
```python
leak_dict = leak.to_dict()
print(leak_dict)
# {
#   'leak_type': 'email',
#   'content': 'admin@company.com',
#   'position': 245,
#   'context': 'Contact admin@company.com for support',
#   'url': 'http://example.onion',
#   'severity': 'medium',
#   'timestamp': '2024-01-17T14:30:22Z'
# }
```

## 🌐 Module `crawler.tor_session`

### Classe `TorSession`

Gère les connexions via le réseau Tor.

#### Constructeur
```python
TorSession(proxy_host: str = '127.0.0.1', proxy_port: int = 9050)
```

#### Méthodes

##### `get(url: str, timeout: int = 30) -> requests.Response`

Effectue une requête GET via Tor.

**Exemple:**
```python
from crawler.tor_session import TorSession

session = TorSession()
response = session.get('http://example.onion')
print(response.text)
```

##### `is_tor_running() -> bool`

Vérifie si Tor est accessible.

**Exemple:**
```python
if session.is_tor_running():
    print("✅ Tor est accessible")
else:
    print("❌ Tor n'est pas accessible")
```

## 📊 Module `reports.generator`

### Classe `ReportGenerator`

Génère des rapports dans différents formats.

#### Méthodes

##### `generate_json_report(leaks: List[LeakDetection]) -> dict`

Génère un rapport au format JSON.

**Exemple:**
```python
from reports.generator import ReportGenerator

generator = ReportGenerator()
json_report = generator.generate_json_report(leaks)
```

##### `generate_markdown_report(leaks: List[LeakDetection]) -> str`

Génère un rapport au format Markdown.

**Exemple:**
```python
markdown_report = generator.generate_markdown_report(leaks)
with open('report.md', 'w') as f:
    f.write(markdown_report)
```

##### `generate_csv_report(leaks: List[LeakDetection]) -> str`

Génère un rapport au format CSV.

**Exemple:**
```python
csv_report = generator.generate_csv_report(leaks)
with open('report.csv', 'w') as f:
    f.write(csv_report)
```

##### `generate_statistics(leaks: List[LeakDetection]) -> dict`

Génère des statistiques sur les fuites.

**Retour:**
```python
{
    'total_leaks': 15,
    'by_type': {
        'email': 8,
        'password': 3,
        'phone': 4
    },
    'by_severity': {
        'high': 5,
        'medium': 7,
        'low': 3
    },
    'scan_duration': '2m 34s'
}
```

## 🔔 Module `notifications.realtime`

### Classe `NotificationManager`

Gère les notifications en temps réel.

#### Constructeur
```python
NotificationManager()
```

#### Méthodes de Configuration

##### `configure_slack(webhook_url: str)`

Configure les notifications Slack.

**Exemple:**
```python
from notifications.realtime import NotificationManager

manager = NotificationManager()
manager.configure_slack('https://hooks.slack.com/services/...')
```

##### `configure_email(smtp_server: str, smtp_port: int, username: str, password: str)`

Configure les notifications email.

**Exemple:**
```python
manager.configure_email(
    smtp_server='smtp.gmail.com',
    smtp_port=587,
    username='user@gmail.com',
    password='app_password'
)
```

##### `configure_discord(webhook_url: str)`

Configure les notifications Discord.

**Exemple:**
```python
manager.configure_discord('https://discord.com/api/webhooks/...')
```

#### Méthodes d'Envoi

##### `send_notification(message: str, priority: str = 'medium', channels: List[str] = None, metadata: dict = None)`

Envoie une notification.

**Paramètres:**
- `message` (str): Message à envoyer
- `priority` (str): Priorité ('low', 'medium', 'high', 'critical')
- `channels` (List[str]): Canaux de notification
- `metadata` (dict): Métadonnées supplémentaires

**Exemple:**
```python
manager.send_notification(
    message="🚨 Fuite critique détectée",
    priority="critical",
    channels=["slack", "email"],
    metadata={'leak_count': 15, 'url': 'http://example.onion'}
)
```

##### `send_leak_alert(leak: LeakDetection)`

Envoie une alerte pour une fuite spécifique.

**Exemple:**
```python
for leak in detected_leaks:
    manager.send_leak_alert(leak)
```

## 🚨 Module `alerts.logger`

### Classe `AlertLogger`

Gère les logs et alertes système.

#### Méthodes

##### `log_detection(leak: LeakDetection)`

Enregistre une détection dans les logs.

##### `log_scan_start(url: str)`

Enregistre le début d'un scan.

##### `log_scan_complete(url: str, leak_count: int, duration: float)`

Enregistre la fin d'un scan.

**Exemple:**
```python
from alerts.logger import AlertLogger

logger = AlertLogger()
logger.log_scan_start('http://example.onion')

# ... scan ...

logger.log_scan_complete('http://example.onion', 15, 120.5)
```

## 📧 Module `alerts.email`

### Classe `EmailAlert`

Gère les alertes par email.

#### Constructeur
```python
EmailAlert(smtp_server: str, smtp_port: int, username: str, password: str)
```

#### Méthodes

##### `send_alert(subject: str, message: str, recipients: List[str])`

Envoie un email d'alerte.

**Exemple:**
```python
from alerts.email import EmailAlert

email_alert = EmailAlert('smtp.gmail.com', 587, 'user@gmail.com', 'password')
email_alert.send_alert(
    subject='DarkCrawler Alert',
    message='15 fuites détectées',
    recipients=['admin@company.com']
)
```

## 🌐 Module `alerts.webhook`

### Classe `WebhookAlert`

Gère les alertes via webhooks.

#### Méthodes

##### `send_slack_alert(webhook_url: str, message: str, priority: str = 'medium')`

Envoie une alerte Slack.

##### `send_discord_alert(webhook_url: str, message: str, priority: str = 'medium')`

Envoie une alerte Discord.

**Exemple:**
```python
from alerts.webhook import WebhookAlert

webhook = WebhookAlert()
webhook.send_slack_alert(
    'https://hooks.slack.com/services/...',
    '🚨 15 fuites détectées sur http://example.onion',
    'high'
)
```

## 🔧 Utilitaires et Helpers

### Fonction `load_config(config_path: str) -> dict`

Charge un fichier de configuration.

**Exemple:**
```python
from config.loader import load_config

config = load_config('config/crawler_config.json')
print(config['tor']['proxy_port'])  # 9050
```

### Fonction `validate_onion_url(url: str) -> bool`

Valide une URL .onion.

**Exemple:**
```python
from utils.validators import validate_onion_url

if validate_onion_url('http://example.onion'):
    print("✅ URL valide")
```

### Fonction `format_duration(seconds: float) -> str`

Formate une durée en texte lisible.

**Exemple:**
```python
from utils.formatters import format_duration

duration = format_duration(125.5)
print(duration)  # "2m 5s"
```

## 🧪 Tests et Mocking

### Classe `MockDetector`

Détecteur simulé pour les tests.

**Exemple:**
```python
from tests.mocks import MockDetector

mock_detector = MockDetector()
mock_detector.add_mock_leak('email', 'test@example.com', 100)

results = mock_detector.scan_url('http://test.onion')
assert len(results) == 1
```

## 🔒 Sécurité et Bonnes Pratiques

### Gestion des Erreurs

Toutes les méthodes peuvent lever les exceptions suivantes:

- `ConnectionError`: Problèmes de réseau/Tor
- `TimeoutError`: Timeout des requêtes
- `ValueError`: Paramètres invalides
- `ConfigurationError`: Erreurs de configuration
- `AuthenticationError`: Erreurs d'authentification (email, webhooks)

### Exemple de Gestion d'Erreurs
```python
from crawler.detector import DataLeakDetector
from crawler.exceptions import ConnectionError, TimeoutError

detector = DataLeakDetector()

try:
    results = detector.scan_url('http://example.onion')
except ConnectionError:
    print("❌ Impossible de se connecter via Tor")
except TimeoutError:
    print("⏰ Timeout de la requête")
except ValueError as e:
    print(f"❌ Paramètre invalide: {e}")
except Exception as e:
    print(f"❌ Erreur inattendue: {e}")
```

### Logging

Configuration recommandée pour les logs:

```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('darkcrawler.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger('DarkCrawler')
```

## 📈 Performance et Optimisation

### Conseils de Performance

1. **Limitation des threads**: Ne pas dépasser 5 threads simultanés
2. **Timeout approprié**: 30-60 secondes selon la connexion
3. **Cache des résultats**: Éviter de rescanner les mêmes URLs
4. **Gestion mémoire**: Traiter les gros volumes par batch

### Exemple d'Optimisation
```python
from concurrent.futures import ThreadPoolExecutor
from crawler.detector import DataLeakDetector

def scan_with_pool(urls, max_workers=3):
    detector = DataLeakDetector()
    results = {}
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {
            executor.submit(detector.scan_url, url): url 
            for url in urls
        }
        
        for future in future_to_url:
            url = future_to_url[future]
            try:
                results[url] = future.result(timeout=60)
            except Exception as e:
                results[url] = []
                print(f"Erreur {url}: {e}")
    
    return results
```

Cette documentation couvre l'ensemble de l'API DarkCrawler. Pour des exemples d'utilisation pratiques, consultez le fichier `EXAMPLES.md`.