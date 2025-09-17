#!/usr/bin/env python3
"""
Système de notifications en temps réel pour DarkCrawler
Gère les notifications WebSocket, push et intégrations tierces
"""

import asyncio
import json
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass, asdict
from enum import Enum
import threading
import queue
import time

# Imports pour les notifications
try:
    from flask_socketio import SocketIO, emit
    SOCKETIO_AVAILABLE = True
except ImportError:
    SOCKETIO_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# Imports DarkCrawler
from alerts.logger import darkcrawler_logger
from crawler.detector import LeakDetection, SeverityLevel


class NotificationType(Enum):
    """Types de notifications"""
    LEAK_DETECTED = "leak_detected"
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    ERROR_OCCURRED = "error_occurred"
    SYSTEM_STATUS = "system_status"


class NotificationPriority(Enum):
    """Priorités des notifications"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Notification:
    """Représente une notification"""
    id: str
    type: NotificationType
    priority: NotificationPriority
    title: str
    message: str
    data: Dict[str, Any]
    timestamp: datetime
    source: str = "DarkCrawler"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit en dictionnaire"""
        return {
            'id': self.id,
            'type': self.type.value,
            'priority': self.priority.value,
            'title': self.title,
            'message': self.message,
            'data': self.data,
            'timestamp': self.timestamp.isoformat(),
            'source': self.source
        }


class NotificationChannel:
    """Canal de notification abstrait"""
    
    def __init__(self, name: str, config: Dict[str, Any] = None):
        self.name = name
        self.config = config or {}
        self.enabled = True
        self.logger = logging.getLogger(f"{__name__}.{name}")
    
    async def send(self, notification: Notification) -> bool:
        """Envoie une notification"""
        raise NotImplementedError
    
    def is_enabled(self) -> bool:
        """Vérifie si le canal est activé"""
        return self.enabled
    
    def disable(self):
        """Désactive le canal"""
        self.enabled = False
    
    def enable(self):
        """Active le canal"""
        self.enabled = True


class WebSocketChannel(NotificationChannel):
    """Canal WebSocket pour notifications en temps réel"""
    
    def __init__(self, socketio_instance: Optional[SocketIO] = None):
        super().__init__("websocket")
        self.socketio = socketio_instance
        self.connected_clients = set()
    
    async def send(self, notification: Notification) -> bool:
        """Envoie via WebSocket"""
        if not self.socketio or not self.is_enabled():
            return False
        
        try:
            # Émettre à tous les clients connectés
            self.socketio.emit('notification', notification.to_dict())
            self.logger.info(f"Notification WebSocket envoyée: {notification.title}")
            return True
        except Exception as e:
            self.logger.error(f"Erreur WebSocket: {e}")
            return False
    
    def add_client(self, client_id: str):
        """Ajoute un client connecté"""
        self.connected_clients.add(client_id)
    
    def remove_client(self, client_id: str):
        """Supprime un client déconnecté"""
        self.connected_clients.discard(client_id)


class SlackChannel(NotificationChannel):
    """Canal Slack pour notifications"""
    
    def __init__(self, webhook_url: str, config: Dict[str, Any] = None):
        super().__init__("slack", config)
        self.webhook_url = webhook_url
    
    async def send(self, notification: Notification) -> bool:
        """Envoie via Slack"""
        if not REQUESTS_AVAILABLE or not self.is_enabled():
            return False
        
        try:
            # Formatage du message Slack
            color_map = {
                NotificationPriority.LOW: "good",
                NotificationPriority.MEDIUM: "warning", 
                NotificationPriority.HIGH: "danger",
                NotificationPriority.CRITICAL: "danger"
            }
            
            payload = {
                "attachments": [{
                    "color": color_map.get(notification.priority, "good"),
                    "title": f"🕸️ {notification.title}",
                    "text": notification.message,
                    "fields": [
                        {
                            "title": "Type",
                            "value": notification.type.value,
                            "short": True
                        },
                        {
                            "title": "Priorité",
                            "value": notification.priority.value.upper(),
                            "short": True
                        },
                        {
                            "title": "Timestamp",
                            "value": notification.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                            "short": True
                        }
                    ],
                    "footer": notification.source,
                    "ts": int(notification.timestamp.timestamp())
                }]
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            self.logger.info(f"Notification Slack envoyée: {notification.title}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur Slack: {e}")
            return False


class DiscordChannel(NotificationChannel):
    """Canal Discord pour notifications"""
    
    def __init__(self, webhook_url: str, config: Dict[str, Any] = None):
        super().__init__("discord", config)
        self.webhook_url = webhook_url
    
    async def send(self, notification: Notification) -> bool:
        """Envoie via Discord"""
        if not REQUESTS_AVAILABLE or not self.is_enabled():
            return False
        
        try:
            # Formatage du message Discord
            color_map = {
                NotificationPriority.LOW: 0x00ff00,      # Vert
                NotificationPriority.MEDIUM: 0xffaa00,   # Orange
                NotificationPriority.HIGH: 0xff4444,     # Rouge
                NotificationPriority.CRITICAL: 0xff0000  # Rouge foncé
            }
            
            embed = {
                "title": f"🕸️ {notification.title}",
                "description": notification.message,
                "color": color_map.get(notification.priority, 0x00ff00),
                "fields": [
                    {
                        "name": "Type",
                        "value": notification.type.value,
                        "inline": True
                    },
                    {
                        "name": "Priorité", 
                        "value": notification.priority.value.upper(),
                        "inline": True
                    }
                ],
                "footer": {
                    "text": notification.source
                },
                "timestamp": notification.timestamp.isoformat()
            }
            
            payload = {"embeds": [embed]}
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            self.logger.info(f"Notification Discord envoyée: {notification.title}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur Discord: {e}")
            return False


class EmailChannel(NotificationChannel):
    """Canal Email pour notifications importantes"""
    
    def __init__(self, smtp_config: Dict[str, Any]):
        super().__init__("email")
        self.smtp_config = smtp_config
    
    async def send(self, notification: Notification) -> bool:
        """Envoie via Email"""
        # Utiliser le système d'email existant de DarkCrawler
        try:
            from alerts.email import EmailAlertSender
            
            email_sender = EmailAlertSender(self.smtp_config)
            
            # Formatage HTML du message
            html_content = f"""
            <html>
            <body>
                <h2 style="color: #333;">🕸️ {notification.title}</h2>
                <p><strong>Type:</strong> {notification.type.value}</p>
                <p><strong>Priorité:</strong> {notification.priority.value.upper()}</p>
                <p><strong>Message:</strong> {notification.message}</p>
                <p><strong>Timestamp:</strong> {notification.timestamp.strftime('%Y-%m-%d %H:%M:%S')}</p>
                <hr>
                <p><em>Source: {notification.source}</em></p>
            </body>
            </html>
            """
            
            success = email_sender.send_alert(
                subject=f"[DarkCrawler] {notification.title}",
                message=notification.message,
                html_content=html_content,
                priority=notification.priority.value
            )
            
            if success:
                self.logger.info(f"Notification Email envoyée: {notification.title}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Erreur Email: {e}")
            return False


class RealtimeNotificationManager:
    """Gestionnaire principal des notifications en temps réel"""
    
    def __init__(self):
        self.channels: Dict[str, NotificationChannel] = {}
        self.notification_queue = queue.Queue()
        self.running = False
        self.worker_thread = None
        self.logger = logging.getLogger(__name__)
        
        # Statistiques
        self.stats = {
            'total_sent': 0,
            'total_failed': 0,
            'by_channel': {},
            'by_priority': {p.value: 0 for p in NotificationPriority}
        }
    
    def add_channel(self, channel: NotificationChannel):
        """Ajoute un canal de notification"""
        self.channels[channel.name] = channel
        self.stats['by_channel'][channel.name] = {'sent': 0, 'failed': 0}
        self.logger.info(f"Canal ajouté: {channel.name}")
    
    def remove_channel(self, channel_name: str):
        """Supprime un canal de notification"""
        if channel_name in self.channels:
            del self.channels[channel_name]
            self.logger.info(f"Canal supprimé: {channel_name}")
    
    def start(self):
        """Démarre le gestionnaire de notifications"""
        if self.running:
            return
        
        self.running = True
        self.worker_thread = threading.Thread(target=self._worker, daemon=True)
        self.worker_thread.start()
        self.logger.info("Gestionnaire de notifications démarré")
    
    def stop(self):
        """Arrête le gestionnaire de notifications"""
        self.running = False
        if self.worker_thread:
            self.worker_thread.join(timeout=5)
        self.logger.info("Gestionnaire de notifications arrêté")
    
    def _worker(self):
        """Thread worker pour traiter les notifications"""
        while self.running:
            try:
                # Récupérer une notification de la queue
                notification = self.notification_queue.get(timeout=1)
                
                # Envoyer via tous les canaux activés
                asyncio.run(self._send_notification(notification))
                
                self.notification_queue.task_done()
                
            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Erreur worker: {e}")
    
    async def _send_notification(self, notification: Notification):
        """Envoie une notification via tous les canaux"""
        for channel_name, channel in self.channels.items():
            if not channel.is_enabled():
                continue
            
            try:
                success = await channel.send(notification)
                
                if success:
                    self.stats['by_channel'][channel_name]['sent'] += 1
                    self.stats['total_sent'] += 1
                else:
                    self.stats['by_channel'][channel_name]['failed'] += 1
                    self.stats['total_failed'] += 1
                    
            except Exception as e:
                self.logger.error(f"Erreur canal {channel_name}: {e}")
                self.stats['by_channel'][channel_name]['failed'] += 1
                self.stats['total_failed'] += 1
        
        # Mettre à jour les stats par priorité
        self.stats['by_priority'][notification.priority.value] += 1
    
    def notify(self, notification: Notification):
        """Ajoute une notification à la queue"""
        if not self.running:
            self.start()
        
        self.notification_queue.put(notification)
        self.logger.debug(f"Notification ajoutée: {notification.title}")
    
    def notify_leak_detected(self, leaks: List[LeakDetection], source_url: str = ""):
        """Notification spécialisée pour les fuites détectées"""
        # Déterminer la priorité basée sur la sévérité maximale
        max_severity = max((leak.severity for leak in leaks), default=SeverityLevel.LOW)
        priority_map = {
            SeverityLevel.LOW: NotificationPriority.LOW,
            SeverityLevel.MEDIUM: NotificationPriority.MEDIUM,
            SeverityLevel.HIGH: NotificationPriority.HIGH,
            SeverityLevel.CRITICAL: NotificationPriority.CRITICAL
        }
        
        priority = priority_map.get(max_severity, NotificationPriority.MEDIUM)
        
        # Créer le message
        leak_count = len(leaks)
        domain = source_url.split('/')[2] if '/' in source_url else source_url
        
        title = f"🚨 {leak_count} fuite(s) détectée(s)"
        if domain:
            title += f" sur {domain}"
        
        message = f"Détection de {leak_count} fuite(s) de données sensibles"
        if domain:
            message += f" sur le site {domain}"
        
        # Données détaillées
        data = {
            'leak_count': leak_count,
            'source_url': source_url,
            'leaks': [
                {
                    'type': leak.type,
                    'severity': leak.severity.value,
                    'confidence': leak.confidence,
                    'value_preview': leak.value[:50] + '...' if len(leak.value) > 50 else leak.value
                }
                for leak in leaks
            ],
            'severity_distribution': {
                severity.value: sum(1 for leak in leaks if leak.severity == severity)
                for severity in SeverityLevel
            }
        }
        
        notification = Notification(
            id=f"leak_{int(time.time())}_{hash(source_url) % 10000}",
            type=NotificationType.LEAK_DETECTED,
            priority=priority,
            title=title,
            message=message,
            data=data,
            timestamp=datetime.now()
        )
        
        self.notify(notification)
    
    def notify_scan_started(self, urls: List[str]):
        """Notification de début de scan"""
        notification = Notification(
            id=f"scan_start_{int(time.time())}",
            type=NotificationType.SCAN_STARTED,
            priority=NotificationPriority.LOW,
            title="🔍 Scan démarré",
            message=f"Début du scan de {len(urls)} URL(s)",
            data={'url_count': len(urls), 'urls': urls[:10]},  # Limiter à 10 URLs
            timestamp=datetime.now()
        )
        
        self.notify(notification)
    
    def notify_scan_completed(self, results: Dict[str, Any]):
        """Notification de fin de scan"""
        total_leaks = results.get('total_leaks', 0)
        priority = NotificationPriority.HIGH if total_leaks > 0 else NotificationPriority.LOW
        
        notification = Notification(
            id=f"scan_complete_{int(time.time())}",
            type=NotificationType.SCAN_COMPLETED,
            priority=priority,
            title="✅ Scan terminé",
            message=f"Scan terminé: {total_leaks} fuite(s) détectée(s)",
            data=results,
            timestamp=datetime.now()
        )
        
        self.notify(notification)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Retourne les statistiques des notifications"""
        return {
            'stats': self.stats,
            'active_channels': list(self.channels.keys()),
            'queue_size': self.notification_queue.qsize(),
            'running': self.running
        }


# Instance globale
notification_manager = RealtimeNotificationManager()


def setup_notifications(config: Dict[str, Any], socketio_instance: SocketIO = None):
    """Configure les canaux de notification"""
    
    # WebSocket (si disponible)
    if SOCKETIO_AVAILABLE and socketio_instance:
        websocket_channel = WebSocketChannel(socketio_instance)
        notification_manager.add_channel(websocket_channel)
    
    # Slack (si configuré)
    if config.get('slack', {}).get('webhook_url'):
        slack_channel = SlackChannel(
            webhook_url=config['slack']['webhook_url'],
            config=config.get('slack', {})
        )
        notification_manager.add_channel(slack_channel)
    
    # Discord (si configuré)
    if config.get('discord', {}).get('webhook_url'):
        discord_channel = DiscordChannel(
            webhook_url=config['discord']['webhook_url'],
            config=config.get('discord', {})
        )
        notification_manager.add_channel(discord_channel)
    
    # Email (si configuré)
    if config.get('email', {}).get('enabled'):
        email_channel = EmailChannel(config['email'])
        notification_manager.add_channel(email_channel)
    
    # Démarrer le gestionnaire
    notification_manager.start()
    
    darkcrawler_logger.info(f"Notifications configurées: {len(notification_manager.channels)} canaux")


if __name__ == "__main__":
    # Test du système de notifications
    print("🔔 Test du système de notifications en temps réel")
    
    # Configuration de test
    test_config = {
        'slack': {
            'webhook_url': 'https://hooks.slack.com/services/TEST/TEST/TEST'
        },
        'discord': {
            'webhook_url': 'https://discord.com/api/webhooks/TEST/TEST'
        }
    }
    
    # Setup (sans WebSocket pour le test)
    setup_notifications(test_config)
    
    # Test de notification
    from crawler.detector import LeakDetection, SeverityLevel
    
    test_leaks = [
        LeakDetection(
            type="email",
            value="admin@test.com",
            context="Contact: admin@test.com",
            severity=SeverityLevel.MEDIUM,
            confidence=0.95,
            position=42,
            timestamp=datetime.now(),
            source_url="http://test.onion"
        )
    ]
    
    notification_manager.notify_leak_detected(test_leaks, "http://test.onion")
    
    # Attendre un peu pour le traitement
    time.sleep(2)
    
    # Afficher les statistiques
    stats = notification_manager.get_statistics()
    print(f"✅ Statistiques: {stats}")
    
    # Arrêter
    notification_manager.stop()