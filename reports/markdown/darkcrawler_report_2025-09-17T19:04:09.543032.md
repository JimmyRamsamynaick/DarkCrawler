# 🕸️ Rapport DarkCrawler

## 📊 Informations générales

- **ID du rapport**: 041d36bc
- **Généré le**: 2025-09-17T19:04:09.542577
- **Version du crawler**: 1.0.0
- **Durée du scan**: 1.00s
- **Sites scannés**: 1
- **Fuites détectées**: 6

## 📈 Statistiques

### Répartition par sévérité
- 🚨 **CRITICAL**: 2 fuites
- ⚠️ **HIGH**: 0 fuites
- ⚡ **MEDIUM**: 1 fuites
- 💡 **LOW**: 3 fuites
- ℹ️ **INFO**: 0 fuites

### Performance
- **Scans réussis**: 1
- **Scans échoués**: 0
- **Temps de réponse moyen**: 0.50s

## 🔍 Détails des scans

### 1. http://demo.onion

- **Statut**: success
- **Timestamp**: 2025-09-17T19:04:09.542712
- **Temps de réponse**: 0.50s
- **Taille de la page**: 12 bytes
- **Fuites détectées**: 6

  1. 🚨 **credit_card** (critical)
     - Contenu: `4532-1234-5678-9012`
     - Confiance: 0.80
     - Position: ligne 171

  2. 🚨 **password** (critical)
     - Contenu: `"mySecretPassword123!";`
     - Confiance: 1.00
     - Position: ligne 363

  3. 💡 **ip_address** (low)
     - Contenu: `192.168.1.100`
     - Confiance: 0.40
     - Position: ligne 262

  4. 💡 **base64_potential** (low)
     - Contenu: `1234567890abcdef`
     - Confiance: 0.80
     - Position: ligne 326

  5. 💡 **base64_potential** (low)
     - Contenu: `mySecretPassword`
     - Confiance: 0.70
     - Position: ligne 375

  6. ⚡ **email** (medium)
     - Contenu: `admin@example.com`
     - Confiance: 0.30
     - Position: ligne 82


---
*Rapport généré par DarkCrawler v1.0.0 le 2025-09-17T19:04:09.542577*
