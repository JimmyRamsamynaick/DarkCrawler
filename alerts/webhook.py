"""
Module d'alertes webhook pour DarkCrawler
Envoie des notifications via webhooks (Slack, Discord, etc.)
"""

import requests
import json
import logging
from typing import List, Dict, Optional, Any
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


class WebhookType(Enum):
    """Types de webhooks supportés"""
    SLACK = "slack"
    DISCORD = "discord"
    TEAMS = "teams"
    GENERIC = "generic"


@dataclass
class WebhookConfig:
    """Configuration pour un webhook"""
    url: str
    webhook_type: WebhookType
    name: str = "DarkCrawler Alert"
    timeout: int = 30
    retry_count: int = 3
    headers: Dict[str, str] = None
    
    def __post_init__(self):
        if self.headers is None:
            self.headers = {"Content-Type": "application/json"}


class WebhookAlertSender:
    """Gestionnaire d'alertes par webhook"""
    
    def __init__(self):
        """Initialise le gestionnaire de webhooks"""
        self.logger = logging.getLogger(__name__)
        self.webhooks = {}
    
    def add_webhook(self, name: str, config: WebhookConfig):
        """
        Ajoute un webhook
        
        Args:
            name: Nom du webhook
            config: Configuration du webhook
        """
        self.webhooks[name] = config
        self.logger.info(f"Webhook ajouté: {name} ({config.webhook_type.value})")
    
    def remove_webhook(self, name: str):
        """
        Supprime un webhook
        
        Args:
            name: Nom du webhook
        """
        if name in self.webhooks:
            del self.webhooks[name]
            self.logger.info(f"Webhook supprimé: {name}")
    
    def send_leak_alert(self, detections: List[Dict], source_url: str = "", 
                       webhook_names: List[str] = None, 
                       additional_info: Dict = None) -> Dict[str, bool]:
        """
        Envoie une alerte de fuite via webhooks
        
        Args:
            detections: Liste des détections
            source_url: URL source de la fuite
            webhook_names: Noms des webhooks à utiliser (tous si None)
            additional_info: Informations supplémentaires
            
        Returns:
            Dict[str, bool]: Résultats d'envoi par webhook
        """
        if not detections:
            self.logger.warning("Aucune détection à envoyer")
            return {}
        
        # Déterminer les webhooks à utiliser
        target_webhooks = webhook_names or list(self.webhooks.keys())
        
        if not target_webhooks:
            self.logger.warning("Aucun webhook configuré")
            return {}
        
        results = {}
        
        for webhook_name in target_webhooks:
            if webhook_name not in self.webhooks:
                self.logger.warning(f"Webhook non trouvé: {webhook_name}")
                results[webhook_name] = False
                continue
            
            config = self.webhooks[webhook_name]
            
            try:
                # Créer le payload selon le type de webhook
                payload = self._create_payload(config.webhook_type, detections, 
                                             source_url, additional_info)
                
                # Envoyer le webhook
                success = self._send_webhook(config, payload)
                results[webhook_name] = success
                
                if success:
                    self.logger.info(f"Alerte envoyée via {webhook_name}")
                else:
                    self.logger.error(f"Échec envoi via {webhook_name}")
                    
            except Exception as e:
                self.logger.error(f"Erreur webhook {webhook_name}: {e}")
                results[webhook_name] = False
        
        return results
    
    def send_summary_report(self, summary_data: Dict, 
                          webhook_names: List[str] = None) -> Dict[str, bool]:
        """
        Envoie un rapport de synthèse via webhooks
        
        Args:
            summary_data: Données de synthèse
            webhook_names: Noms des webhooks à utiliser
            
        Returns:
            Dict[str, bool]: Résultats d'envoi par webhook
        """
        target_webhooks = webhook_names or list(self.webhooks.keys())
        results = {}
        
        for webhook_name in target_webhooks:
            if webhook_name not in self.webhooks:
                results[webhook_name] = False
                continue
            
            config = self.webhooks[webhook_name]
            
            try:
                payload = self._create_summary_payload(config.webhook_type, summary_data)
                success = self._send_webhook(config, payload)
                results[webhook_name] = success
                
            except Exception as e:
                self.logger.error(f"Erreur rapport webhook {webhook_name}: {e}")
                results[webhook_name] = False
        
        return results
    
    def _send_webhook(self, config: WebhookConfig, payload: Dict) -> bool:
        """
        Envoie un webhook avec retry
        
        Args:
            config: Configuration du webhook
            payload: Données à envoyer
            
        Returns:
            bool: Succès de l'envoi
        """
        for attempt in range(config.retry_count):
            try:
                response = requests.post(
                    config.url,
                    json=payload,
                    headers=config.headers,
                    timeout=config.timeout
                )
                
                if response.status_code in [200, 201, 204]:
                    return True
                else:
                    self.logger.warning(
                        f"Webhook réponse {response.status_code}: {response.text}"
                    )
                    
            except requests.exceptions.RequestException as e:
                self.logger.warning(f"Tentative {attempt + 1} échouée: {e}")
                
                if attempt < config.retry_count - 1:
                    # Attendre avant de réessayer
                    import time
                    time.sleep(2 ** attempt)  # Backoff exponentiel
        
        return False
    
    def _create_payload(self, webhook_type: WebhookType, detections: List[Dict], 
                       source_url: str, additional_info: Dict = None) -> Dict:
        """
        Crée le payload selon le type de webhook
        
        Args:
            webhook_type: Type de webhook
            detections: Liste des détections
            source_url: URL source
            additional_info: Informations supplémentaires
            
        Returns:
            Dict: Payload formaté
        """
        if webhook_type == WebhookType.SLACK:
            return self._create_slack_payload(detections, source_url, additional_info)
        elif webhook_type == WebhookType.DISCORD:
            return self._create_discord_payload(detections, source_url, additional_info)
        elif webhook_type == WebhookType.TEAMS:
            return self._create_teams_payload(detections, source_url, additional_info)
        else:
            return self._create_generic_payload(detections, source_url, additional_info)
    
    def _create_slack_payload(self, detections: List[Dict], source_url: str, 
                             additional_info: Dict = None) -> Dict:
        """Crée un payload Slack"""
        # Déterminer la couleur selon la sévérité
        max_severity = self._get_max_severity(detections)
        color_map = {
            'critical': '#FF0000',
            'high': '#FF8C00',
            'medium': '#FFD700',
            'low': '#32CD32'
        }
        color = color_map.get(max_severity, '#808080')
        
        # Créer les champs
        fields = [
            {
                "title": "Fuites détectées",
                "value": str(len(detections)),
                "short": True
            },
            {
                "title": "Sévérité maximale",
                "value": max_severity.upper(),
                "short": True
            }
        ]
        
        if source_url:
            fields.append({
                "title": "Source",
                "value": f"<{source_url}|{source_url}>",
                "short": False
            })
        
        # Ajouter les détections principales
        critical_detections = [d for d in detections if d.get('severity') == 'critical']
        if critical_detections:
            detection_text = "\n".join([
                f"• {d.get('type', 'Unknown')}: `{d.get('value', 'N/A')}`"
                for d in critical_detections[:5]
            ])
            if len(critical_detections) > 5:
                detection_text += f"\n... et {len(critical_detections) - 5} autres"
            
            fields.append({
                "title": "Détections critiques",
                "value": detection_text,
                "short": False
            })
        
        payload = {
            "attachments": [
                {
                    "color": color,
                    "title": "🚨 DarkCrawler - Alerte de Fuite",
                    "text": f"Détection automatique de {len(detections)} fuite(s) de données sensibles",
                    "fields": fields,
                    "footer": "DarkCrawler Alert System",
                    "ts": int(datetime.now().timestamp())
                }
            ]
        }
        
        return payload
    
    def _create_discord_payload(self, detections: List[Dict], source_url: str, 
                               additional_info: Dict = None) -> Dict:
        """Crée un payload Discord"""
        max_severity = self._get_max_severity(detections)
        
        # Couleurs Discord (décimal)
        color_map = {
            'critical': 16711680,  # Rouge
            'high': 16753920,      # Orange
            'medium': 16776960,    # Jaune
            'low': 3329330         # Vert
        }
        color = color_map.get(max_severity, 8421504)  # Gris par défaut
        
        # Créer l'embed
        embed = {
            "title": "🚨 DarkCrawler - Alerte de Fuite",
            "description": f"Détection automatique de **{len(detections)}** fuite(s) de données sensibles",
            "color": color,
            "timestamp": datetime.now().isoformat(),
            "footer": {
                "text": "DarkCrawler Alert System"
            },
            "fields": [
                {
                    "name": "📊 Statistiques",
                    "value": f"**Fuites:** {len(detections)}\n**Sévérité max:** {max_severity.upper()}",
                    "inline": True
                }
            ]
        }
        
        if source_url:
            embed["fields"].append({
                "name": "🌐 Source",
                "value": f"[{source_url}]({source_url})",
                "inline": False
            })
        
        # Ajouter les détections critiques
        critical_detections = [d for d in detections if d.get('severity') == 'critical']
        if critical_detections:
            detection_text = "\n".join([
                f"• **{d.get('type', 'Unknown')}:** `{d.get('value', 'N/A')}`"
                for d in critical_detections[:5]
            ])
            if len(critical_detections) > 5:
                detection_text += f"\n... et {len(critical_detections) - 5} autres"
            
            embed["fields"].append({
                "name": "🔴 Détections Critiques",
                "value": detection_text,
                "inline": False
            })
        
        payload = {
            "embeds": [embed]
        }
        
        return payload
    
    def _create_teams_payload(self, detections: List[Dict], source_url: str, 
                             additional_info: Dict = None) -> Dict:
        """Crée un payload Microsoft Teams"""
        max_severity = self._get_max_severity(detections)
        
        # Couleurs Teams
        color_map = {
            'critical': 'attention',
            'high': 'warning',
            'medium': 'good',
            'low': 'accent'
        }
        theme_color = color_map.get(max_severity, 'default')
        
        payload = {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": "DarkCrawler Alert",
            "themeColor": theme_color,
            "title": "🚨 DarkCrawler - Alerte de Fuite",
            "text": f"Détection automatique de **{len(detections)}** fuite(s) de données sensibles",
            "sections": [
                {
                    "activityTitle": "Statistiques",
                    "facts": [
                        {
                            "name": "Fuites détectées:",
                            "value": str(len(detections))
                        },
                        {
                            "name": "Sévérité maximale:",
                            "value": max_severity.upper()
                        }
                    ]
                }
            ]
        }
        
        if source_url:
            payload["sections"][0]["facts"].append({
                "name": "Source:",
                "value": source_url
            })
        
        return payload
    
    def _create_generic_payload(self, detections: List[Dict], source_url: str, 
                               additional_info: Dict = None) -> Dict:
        """Crée un payload générique"""
        payload = {
            "alert_type": "data_leak",
            "timestamp": datetime.now().isoformat(),
            "source_url": source_url,
            "detections_count": len(detections),
            "max_severity": self._get_max_severity(detections),
            "detections": detections
        }
        
        if additional_info:
            payload["additional_info"] = additional_info
        
        return payload
    
    def _create_summary_payload(self, webhook_type: WebhookType, 
                               summary_data: Dict) -> Dict:
        """
        Crée un payload pour le rapport de synthèse
        
        Args:
            webhook_type: Type de webhook
            summary_data: Données de synthèse
            
        Returns:
            Dict: Payload formaté
        """
        if webhook_type == WebhookType.SLACK:
            return {
                "attachments": [
                    {
                        "color": "#36a64f",
                        "title": "📊 DarkCrawler - Rapport de Synthèse",
                        "text": f"Rapport pour la période: {summary_data.get('period', 'N/A')}",
                        "fields": [
                            {
                                "title": "Scans effectués",
                                "value": str(summary_data.get('total_scans', 0)),
                                "short": True
                            },
                            {
                                "title": "Sites analysés",
                                "value": str(summary_data.get('sites_analyzed', 0)),
                                "short": True
                            },
                            {
                                "title": "Fuites détectées",
                                "value": str(summary_data.get('total_leaks', 0)),
                                "short": True
                            },
                            {
                                "title": "Taux de détection",
                                "value": f"{summary_data.get('detection_rate', 0):.2%}",
                                "short": True
                            }
                        ],
                        "footer": "DarkCrawler Report System",
                        "ts": int(datetime.now().timestamp())
                    }
                ]
            }
        
        elif webhook_type == WebhookType.DISCORD:
            return {
                "embeds": [
                    {
                        "title": "📊 DarkCrawler - Rapport de Synthèse",
                        "description": f"Rapport pour la période: **{summary_data.get('period', 'N/A')}**",
                        "color": 3329330,  # Vert
                        "timestamp": datetime.now().isoformat(),
                        "fields": [
                            {
                                "name": "📈 Statistiques",
                                "value": (
                                    f"**Scans:** {summary_data.get('total_scans', 0)}\n"
                                    f"**Sites:** {summary_data.get('sites_analyzed', 0)}\n"
                                    f"**Fuites:** {summary_data.get('total_leaks', 0)}\n"
                                    f"**Taux:** {summary_data.get('detection_rate', 0):.2%}"
                                ),
                                "inline": True
                            }
                        ],
                        "footer": {
                            "text": "DarkCrawler Report System"
                        }
                    }
                ]
            }
        
        else:
            return {
                "report_type": "summary",
                "timestamp": datetime.now().isoformat(),
                "data": summary_data
            }
    
    def _get_max_severity(self, detections: List[Dict]) -> str:
        """
        Détermine la sévérité maximale des détections
        
        Args:
            detections: Liste des détections
            
        Returns:
            str: Sévérité maximale
        """
        severity_order = ['critical', 'high', 'medium', 'low']
        
        for severity in severity_order:
            if any(d.get('severity') == severity for d in detections):
                return severity
        
        return 'low'
    
    def test_webhook(self, webhook_name: str) -> bool:
        """
        Teste un webhook
        
        Args:
            webhook_name: Nom du webhook à tester
            
        Returns:
            bool: Succès du test
        """
        if webhook_name not in self.webhooks:
            self.logger.error(f"Webhook non trouvé: {webhook_name}")
            return False
        
        config = self.webhooks[webhook_name]
        
        # Créer un payload de test
        test_payload = {
            "text": "🧪 Test de connexion DarkCrawler",
            "timestamp": datetime.now().isoformat()
        }
        
        if config.webhook_type == WebhookType.SLACK:
            test_payload = {
                "text": "🧪 Test de connexion DarkCrawler - Webhook fonctionnel ✅"
            }
        elif config.webhook_type == WebhookType.DISCORD:
            test_payload = {
                "content": "🧪 Test de connexion DarkCrawler - Webhook fonctionnel ✅"
            }
        
        try:
            success = self._send_webhook(config, test_payload)
            if success:
                self.logger.info(f"Test webhook {webhook_name} réussi")
            else:
                self.logger.error(f"Test webhook {webhook_name} échoué")
            return success
            
        except Exception as e:
            self.logger.error(f"Erreur test webhook {webhook_name}: {e}")
            return False


if __name__ == "__main__":
    # Test du module
    logging.basicConfig(level=logging.INFO)
    
    print("🔗 Test du module WebhookAlertSender")
    
    # Créer le gestionnaire
    webhook_sender = WebhookAlertSender()
    
    # Ajouter des webhooks de test (URLs fictives)
    slack_config = WebhookConfig(
        url="https://hooks.slack.com/services/TEST/TEST/TEST",
        webhook_type=WebhookType.SLACK,
        name="Test Slack"
    )
    
    discord_config = WebhookConfig(
        url="https://discord.com/api/webhooks/TEST/TEST",
        webhook_type=WebhookType.DISCORD,
        name="Test Discord"
    )
    
    webhook_sender.add_webhook("slack_test", slack_config)
    webhook_sender.add_webhook("discord_test", discord_config)
    
    # Test de détections
    test_detections = [
        {
            'type': 'email',
            'value': 'admin@company.com',
            'severity': 'medium',
            'confidence': 0.95
        },
        {
            'type': 'password',
            'value': 'SuperSecret123',
            'severity': 'critical',
            'confidence': 0.88
        }
    ]
    
    print("✅ Webhooks configurés")
    print("✅ Détections de test préparées")
    print("ℹ️ Pour tester l'envoi, configurez des URLs de webhook valides")