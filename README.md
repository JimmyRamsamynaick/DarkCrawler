# 🕸️ DarkCrawler

Un crawler Python avancé pour explorer le dark web via Tor et détecter des fuites de données sensibles.

## 🎯 Objectif

DarkCrawler est un outil de veille sécuritaire qui permet de :
- Explorer le dark web via le réseau Tor
- Détecter des fuites de données sensibles (emails, identifiants, mots de passe)
- Générer des alertes en temps réel
- Produire des rapports détaillés

## 🛠️ Fonctionnalités

### 1. Connexion Tor
- Proxy SOCKS5 (127.0.0.1:9050)
- Vérification automatique de Tor
- Gestion des erreurs de connexion

### 2. Crawler Intelligent
- Scraping éthique des sites .onion
- Gestion des redirections et timeouts
- Parser HTML avec BeautifulSoup

### 3. Détection de Fuites
- Emails : `[\w\.-]+@[\w\.-]+\.\w+`
- Identifiants : `username[:=]\s*\w+`
- Mots de passe : `password[:=]\s*\w+`
- Regex personnalisables

### 4. Système d'Alertes
- Email (SMTP)
- Webhooks (Slack/Discord)
- Console avec niveaux de gravité

### 5. Rapports Automatiques
- Formats : JSON, Markdown, CSV
- Métadonnées complètes
- Export PDF (bonus)

## 🚀 Installation

```bash
pip install -r requirements.txt
```

## 📖 Usage

```bash
python main.py --config config/keywords.json --output reports/
```

## ⚠️ Avertissement Éthique

Ce projet est destiné uniquement à des fins éducatives et de veille légale. 
Ne pas utiliser pour des activités illégales ou malveillantes.

## 👨‍💻 Auteur

Jimmy Ramsamynaick (jimmyramsamynaick@gmail.com)