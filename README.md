# 🕸️ DarkCrawler

Un crawler Python avancé pour explorer le dark web via Tor et détecter des fuites de données sensibles.

## 🎯 Objectif

DarkCrawler est un outil de veille sécuritaire qui permet de :
- Explorer le dark web via le réseau Tor
- Détecter des fuites de données sensibles (emails, identifiants, mots de passe)
- Générer des alertes en temps réel
- Produire des rapports détaillés
- Interface web moderne pour visualisation
- Notifications en temps réel multi-canaux

## 🛠️ Fonctionnalités

### 1. Connexion Tor
- Proxy SOCKS5 (127.0.0.1:9050)
- Vérification automatique de Tor
- Gestion des erreurs de connexion
- Support des circuits multiples

### 2. Crawler Intelligent
- Scraping éthique des sites .onion
- Gestion des redirections et timeouts
- Parser HTML avec BeautifulSoup
- Détection automatique d'encodage
- Respect des robots.txt

### 3. Détection de Fuites
- **Emails** : `[\w\.-]+@[\w\.-]+\.\w+`
- **Identifiants** : `username[:=]\s*\w+`
- **Mots de passe** : `password[:=]\s*\w+`
- **Numéros de téléphone** : `\+?[\d\s\-\(\)]{10,}`
- **Cartes de crédit** : `\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}`
- Regex personnalisables via configuration

### 4. Système d'Alertes Multi-Canal
- **Email** (SMTP) avec templates HTML
- **Webhooks** (Slack/Discord/Teams)
- **Console** avec niveaux de gravité
- **Notifications temps réel** via WebSocket
- **Intégrations** : Telegram, PagerDuty

### 5. Rapports Automatiques
- **Formats** : JSON, Markdown, CSV, PDF
- **Métadonnées complètes** : timestamps, sources, contexte
- **Statistiques** : graphiques, tendances
- **Export** : téléchargement direct via interface web

### 6. Interface Web Moderne
- **Dashboard** interactif avec graphiques
- **Visualisation** des détections en temps réel
- **Gestion** des configurations
- **Téléchargement** des rapports
- **API REST** pour intégrations

## 🚀 Installation

### Prérequis
- Python 3.8+
- Tor Browser ou service Tor
- Connexion internet

### Installation rapide
```bash
# Cloner le repository
git clone https://github.com/username/DarkCrawler.git
cd DarkCrawler

# Installer les dépendances
pip install -r requirements.txt

# Démarrer Tor (si pas déjà fait)
# Sur macOS : brew install tor && tor
# Sur Ubuntu : sudo apt install tor && sudo systemctl start tor
```

## 📖 Usage

### 1. Utilisation en ligne de commande

#### Scan basique
```bash
python main.py --config config/keywords.json --output reports/
```

#### Scan avec options avancées
```bash
python main.py \
  --config config/keywords.json \
  --output reports/ \
  --max-depth 3 \
  --timeout 30 \
  --threads 5 \
  --verbose
```

#### Test de démonstration
```bash
python test_demo.py
```

### 2. Interface Web

#### Démarrer l'interface web
```bash
python web_interface.py
```
Puis ouvrir : http://localhost:5001

#### Fonctionnalités web
- **Dashboard** : Vue d'ensemble des détections
- **Rapports** : Visualisation et téléchargement
- **Configuration** : Gestion des paramètres
- **Temps réel** : Notifications live via WebSocket

### 3. Utilisation programmatique

#### Exemple basique
```python
from crawler.detector import DataLeakDetector
from config.crawler_config import load_config

# Initialiser le détecteur
detector = DataLeakDetector()

# Charger la configuration
config = load_config('config/crawler_config.json')

# Scanner une URL
results = detector.scan_url('http://example.onion')

# Traiter les résultats
for leak in results:
    print(f"Fuite détectée: {leak.leak_type} à la position {leak.position}")
```

#### Exemple avancé avec notifications
```python
from notifications.realtime import NotificationManager
from crawler.detector import DataLeakDetector

# Configurer les notifications
notif_manager = NotificationManager()
notif_manager.configure_slack('your-webhook-url')
notif_manager.configure_email('smtp.gmail.com', 587, 'user', 'pass')

# Scanner avec notifications
detector = DataLeakDetector()
results = detector.scan_url('http://example.onion')

# Envoyer notifications
for leak in results:
    notif_manager.send_notification(
        message=f"Fuite détectée: {leak.leak_type}",
        priority='high',
        channels=['slack', 'email']
    )
```

## 🔧 Configuration

### Fichier de configuration principal
```json
{
  "tor": {
    "proxy_host": "127.0.0.1",
    "proxy_port": 9050,
    "timeout": 30
  },
  "crawler": {
    "max_depth": 2,
    "delay": 1,
    "user_agent": "Mozilla/5.0...",
    "max_threads": 3
  },
  "detection": {
    "patterns": {
      "email": "[\\w\\.-]+@[\\w\\.-]+\\.\\w+",
      "phone": "\\+?[\\d\\s\\-\\(\\)]{10,}",
      "credit_card": "\\d{4}[\\s\\-]?\\d{4}[\\s\\-]?\\d{4}[\\s\\-]?\\d{4}"
    }
  },
  "alerts": {
    "email": {
      "enabled": true,
      "smtp_server": "smtp.gmail.com",
      "smtp_port": 587
    },
    "webhook": {
      "enabled": true,
      "slack_url": "https://hooks.slack.com/..."
    }
  }
}
```

### Mots-clés personnalisés
```json
{
  "keywords": [
    "password",
    "login",
    "database",
    "confidential",
    "secret"
  ],
  "domains": [
    "company.com",
    "organization.org"
  ]
}
```

## 📊 Exemples de Rapports

### Rapport JSON
```json
{
  "scan_id": "scan_20240117_143022",
  "timestamp": "2024-01-17T14:30:22Z",
  "total_leaks": 15,
  "leaks": [
    {
      "leak_type": "email",
      "content": "admin@company.com",
      "position": 245,
      "context": "Contact: admin@company.com for support",
      "url": "http://example.onion/contact",
      "severity": "medium"
    }
  ],
  "statistics": {
    "emails": 8,
    "passwords": 3,
    "phones": 4
  }
}
```

### Rapport Markdown
```markdown
# 🔍 Rapport de Scan DarkCrawler

**Date**: 2024-01-17 14:30:22  
**Durée**: 2m 34s  
**URLs scannées**: 12  
**Fuites détectées**: 15  

## 📈 Statistiques

| Type | Nombre | Pourcentage |
|------|--------|-------------|
| Emails | 8 | 53.3% |
| Mots de passe | 3 | 20.0% |
| Téléphones | 4 | 26.7% |

## 🚨 Détections

### Email - Gravité: Moyenne
- **Contenu**: admin@company.com
- **Position**: 245
- **Contexte**: Contact: admin@company.com for support
- **URL**: http://example.onion/contact
```

## 🔔 Notifications

### Configuration Slack
```python
from notifications.realtime import NotificationManager

manager = NotificationManager()
manager.configure_slack('https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK')
```

### Configuration Email
```python
manager.configure_email(
    smtp_server='smtp.gmail.com',
    smtp_port=587,
    username='your-email@gmail.com',
    password='your-app-password'
)
```

### Configuration Discord
```python
manager.configure_discord('https://discord.com/api/webhooks/YOUR/WEBHOOK')
```

## 🧪 Tests

### Lancer tous les tests
```bash
python -m pytest tests/ -v
```

### Test de démonstration
```bash
python test_demo.py
```

### Test de l'interface web
```bash
python web_interface.py
# Ouvrir http://localhost:5001 dans le navigateur
```

## 🐛 Dépannage

### Problèmes courants

#### Tor non accessible
```bash
# Vérifier que Tor fonctionne
curl --socks5 127.0.0.1:9050 http://check.torproject.org/

# Redémarrer Tor si nécessaire
sudo systemctl restart tor
```

#### Port 5000 occupé (macOS)
```bash
# L'interface web utilise le port 5001 par défaut
# Si problème, modifier dans web_interface.py
```

#### Erreurs de dépendances
```bash
pip install --upgrade -r requirements.txt
```

## 📚 API Documentation

### Classe DataLeakDetector

#### Méthodes principales
- `scan_url(url)` : Scanner une URL spécifique
- `scan_multiple(urls)` : Scanner plusieurs URLs
- `detect_leaks(content)` : Détecter des fuites dans du contenu

#### Exemple d'utilisation
```python
detector = DataLeakDetector()
results = detector.scan_url('http://example.onion')
```

### Classe NotificationManager

#### Méthodes de configuration
- `configure_slack(webhook_url)`
- `configure_email(server, port, user, password)`
- `configure_discord(webhook_url)`

#### Envoi de notifications
```python
manager.send_notification(
    message="Fuite détectée",
    priority="high",
    channels=["slack", "email"]
)
```

## 🤝 Contribution

### Développement local
```bash
# Fork le projet
git clone https://github.com/your-username/DarkCrawler.git

# Créer une branche
git checkout -b feature/nouvelle-fonctionnalite

# Installer en mode développement
pip install -e .

# Lancer les tests
python -m pytest
```

### Guidelines
- Suivre PEP 8 pour le style de code
- Ajouter des tests pour les nouvelles fonctionnalités
- Documenter les nouvelles APIs
- Respecter l'éthique et la légalité

## ⚠️ Avertissement Éthique

Ce projet est destiné uniquement à des fins éducatives et de veille légale. 
Ne pas utiliser pour des activités illégales ou malveillantes.

## 👨‍💻 Auteur

Jimmy Ramsamynaick (jimmyramsamynaick@gmail.com)