"""
Module d'alertes par email pour DarkCrawler
Envoie des notifications par email lors de détection de fuites
"""

import smtplib
import ssl
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from typing import List, Dict, Optional, Any
from datetime import datetime
from dataclasses import dataclass
import json
import os


@dataclass
class EmailConfig:
    """Configuration pour l'envoi d'emails"""
    smtp_server: str
    smtp_port: int
    username: str
    password: str
    sender_email: str
    sender_name: str = "DarkCrawler Alert System"
    use_tls: bool = True
    use_ssl: bool = False


class EmailAlertSender:
    """Gestionnaire d'alertes par email"""
    
    def __init__(self, config: EmailConfig):
        """
        Initialise le gestionnaire d'emails
        
        Args:
            config: Configuration email
        """
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Vérifier la configuration
        self._validate_config()
    
    def _validate_config(self):
        """Valide la configuration email"""
        required_fields = ['smtp_server', 'smtp_port', 'username', 'password', 'sender_email']
        
        for field in required_fields:
            if not getattr(self.config, field):
                raise ValueError(f"Configuration email manquante: {field}")
        
        # Vérifier le port
        if not isinstance(self.config.smtp_port, int) or self.config.smtp_port <= 0:
            raise ValueError("Port SMTP invalide")
    
    def send_leak_alert(self, detections: List[Dict], recipients: List[str], 
                       source_url: str = "", additional_info: Dict = None) -> bool:
        """
        Envoie une alerte de fuite détectée
        
        Args:
            detections: Liste des détections
            recipients: Liste des destinataires
            source_url: URL source de la fuite
            additional_info: Informations supplémentaires
            
        Returns:
            bool: Succès de l'envoi
        """
        try:
            if not detections:
                self.logger.warning("Aucune détection à envoyer")
                return False
            
            if not recipients:
                self.logger.warning("Aucun destinataire spécifié")
                return False
            
            # Créer le message
            subject = self._create_subject(detections, source_url)
            body_html = self._create_html_body(detections, source_url, additional_info)
            body_text = self._create_text_body(detections, source_url, additional_info)
            
            # Envoyer à chaque destinataire
            success_count = 0
            for recipient in recipients:
                if self._send_email(recipient, subject, body_html, body_text):
                    success_count += 1
            
            self.logger.info(f"Alertes envoyées: {success_count}/{len(recipients)}")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Erreur envoi alerte email: {e}")
            return False
    
    def send_summary_report(self, summary_data: Dict, recipients: List[str]) -> bool:
        """
        Envoie un rapport de synthèse
        
        Args:
            summary_data: Données de synthèse
            recipients: Liste des destinataires
            
        Returns:
            bool: Succès de l'envoi
        """
        try:
            subject = f"DarkCrawler - Rapport de synthèse du {datetime.now().strftime('%d/%m/%Y')}"
            
            body_html = self._create_summary_html(summary_data)
            body_text = self._create_summary_text(summary_data)
            
            # Envoyer à chaque destinataire
            success_count = 0
            for recipient in recipients:
                if self._send_email(recipient, subject, body_html, body_text):
                    success_count += 1
            
            self.logger.info(f"Rapports de synthèse envoyés: {success_count}/{len(recipients)}")
            return success_count > 0
            
        except Exception as e:
            self.logger.error(f"Erreur envoi rapport: {e}")
            return False
    
    def _send_email(self, recipient: str, subject: str, 
                   body_html: str, body_text: str, 
                   attachments: List[str] = None) -> bool:
        """
        Envoie un email
        
        Args:
            recipient: Destinataire
            subject: Sujet
            body_html: Corps HTML
            body_text: Corps texte
            attachments: Liste des pièces jointes
            
        Returns:
            bool: Succès de l'envoi
        """
        try:
            # Créer le message
            message = MIMEMultipart("alternative")
            message["Subject"] = subject
            message["From"] = f"{self.config.sender_name} <{self.config.sender_email}>"
            message["To"] = recipient
            
            # Ajouter les corps de message
            part_text = MIMEText(body_text, "plain", "utf-8")
            part_html = MIMEText(body_html, "html", "utf-8")
            
            message.attach(part_text)
            message.attach(part_html)
            
            # Ajouter les pièces jointes
            if attachments:
                for attachment_path in attachments:
                    if os.path.exists(attachment_path):
                        self._add_attachment(message, attachment_path)
            
            # Créer la connexion SMTP
            context = ssl.create_default_context()
            
            if self.config.use_ssl:
                server = smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port, context=context)
            else:
                server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)
                if self.config.use_tls:
                    server.starttls(context=context)
            
            # Authentification et envoi
            server.login(self.config.username, self.config.password)
            server.sendmail(self.config.sender_email, recipient, message.as_string())
            server.quit()
            
            self.logger.info(f"Email envoyé avec succès à {recipient}")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur envoi email à {recipient}: {e}")
            return False
    
    def _add_attachment(self, message: MIMEMultipart, file_path: str):
        """
        Ajoute une pièce jointe au message
        
        Args:
            message: Message email
            file_path: Chemin du fichier
        """
        try:
            with open(file_path, "rb") as attachment:
                part = MIMEBase('application', 'octet-stream')
                part.set_payload(attachment.read())
            
            encoders.encode_base64(part)
            
            filename = os.path.basename(file_path)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {filename}'
            )
            
            message.attach(part)
            
        except Exception as e:
            self.logger.error(f"Erreur ajout pièce jointe {file_path}: {e}")
    
    def _create_subject(self, detections: List[Dict], source_url: str) -> str:
        """
        Crée le sujet de l'email d'alerte
        
        Args:
            detections: Liste des détections
            source_url: URL source
            
        Returns:
            str: Sujet de l'email
        """
        severity_counts = {}
        for detection in detections:
            severity = detection.get('severity', 'unknown')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Déterminer la sévérité maximale
        severity_order = ['critical', 'high', 'medium', 'low']
        max_severity = 'low'
        
        for severity in severity_order:
            if severity in severity_counts:
                max_severity = severity
                break
        
        # Créer le sujet
        total_count = len(detections)
        severity_emoji = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': 'ℹ️'
        }
        
        emoji = severity_emoji.get(max_severity, '🔍')
        
        if source_url:
            domain = source_url.split('/')[2] if '/' in source_url else source_url
            subject = f"{emoji} DarkCrawler Alert - {total_count} fuite(s) détectée(s) sur {domain}"
        else:
            subject = f"{emoji} DarkCrawler Alert - {total_count} fuite(s) détectée(s)"
        
        return subject
    
    def _create_html_body(self, detections: List[Dict], source_url: str, 
                         additional_info: Dict = None) -> str:
        """
        Crée le corps HTML de l'email
        
        Args:
            detections: Liste des détections
            source_url: URL source
            additional_info: Informations supplémentaires
            
        Returns:
            str: Corps HTML
        """
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #f44336; color: white; padding: 15px; border-radius: 5px; }}
                .detection {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .critical {{ border-left: 5px solid #f44336; }}
                .high {{ border-left: 5px solid #ff9800; }}
                .medium {{ border-left: 5px solid #ffeb3b; }}
                .low {{ border-left: 5px solid #4caf50; }}
                .context {{ background-color: #f5f5f5; padding: 10px; margin: 10px 0; font-family: monospace; }}
                .footer {{ margin-top: 30px; padding: 15px; background-color: #f0f0f0; border-radius: 5px; }}
                .stats {{ display: flex; justify-content: space-around; margin: 20px 0; }}
                .stat {{ text-align: center; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🚨 DarkCrawler - Alerte de Fuite Détectée</h1>
                <p>Détection automatique de données sensibles</p>
            </div>
            
            <h2>📊 Résumé</h2>
            <div class="stats">
                <div class="stat">
                    <h3>{len(detections)}</h3>
                    <p>Fuites détectées</p>
                </div>
                <div class="stat">
                    <h3>{len(set(d.get('type', '') for d in detections))}</h3>
                    <p>Types différents</p>
                </div>
                <div class="stat">
                    <h3>{datetime.now().strftime('%H:%M')}</h3>
                    <p>Heure de détection</p>
                </div>
            </div>
        """
        
        if source_url:
            html += f"""
            <h2>🌐 Source</h2>
            <p><strong>URL:</strong> <code>{source_url}</code></p>
            """
        
        html += "<h2>🔍 Détections</h2>"
        
        # Grouper par sévérité
        by_severity = {}
        for detection in detections:
            severity = detection.get('severity', 'unknown')
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(detection)
        
        # Afficher par ordre de sévérité
        severity_order = ['critical', 'high', 'medium', 'low']
        for severity in severity_order:
            if severity in by_severity:
                html += f"<h3>🔴 Sévérité: {severity.upper()}</h3>"
                
                for detection in by_severity[severity]:
                    html += f"""
                    <div class="detection {severity}">
                        <h4>{detection.get('type', 'Unknown').replace('_', ' ').title()}</h4>
                        <p><strong>Valeur:</strong> <code>{detection.get('value', 'N/A')}</code></p>
                        <p><strong>Confiance:</strong> {detection.get('confidence', 0):.2%}</p>
                        <div class="context">
                            <strong>Contexte:</strong><br>
                            {detection.get('context', 'N/A')}
                        </div>
                    </div>
                    """
        
        # Informations supplémentaires
        if additional_info:
            html += "<h2>ℹ️ Informations supplémentaires</h2>"
            for key, value in additional_info.items():
                html += f"<p><strong>{key}:</strong> {value}</p>"
        
        html += f"""
            <div class="footer">
                <p><strong>⚠️ Important:</strong> Cette alerte a été générée automatiquement par DarkCrawler.</p>
                <p><strong>🕐 Timestamp:</strong> {datetime.now().isoformat()}</p>
                <p><strong>🔒 Sécurité:</strong> Vérifiez immédiatement ces fuites et prenez les mesures appropriées.</p>
            </div>
        </body>
        </html>
        """
        
        return html
    
    def _create_text_body(self, detections: List[Dict], source_url: str, 
                         additional_info: Dict = None) -> str:
        """
        Crée le corps texte de l'email
        
        Args:
            detections: Liste des détections
            source_url: URL source
            additional_info: Informations supplémentaires
            
        Returns:
            str: Corps texte
        """
        text = "🚨 DARKCRAWLER - ALERTE DE FUITE DÉTECTÉE\n"
        text += "=" * 50 + "\n\n"
        
        text += f"📊 RÉSUMÉ\n"
        text += f"Fuites détectées: {len(detections)}\n"
        text += f"Types différents: {len(set(d.get('type', '') for d in detections))}\n"
        text += f"Heure: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}\n\n"
        
        if source_url:
            text += f"🌐 SOURCE\n"
            text += f"URL: {source_url}\n\n"
        
        text += "🔍 DÉTECTIONS\n"
        text += "-" * 30 + "\n"
        
        for i, detection in enumerate(detections, 1):
            text += f"\n[{i}] {detection.get('type', 'Unknown').replace('_', ' ').title()}\n"
            text += f"    Valeur: {detection.get('value', 'N/A')}\n"
            text += f"    Sévérité: {detection.get('severity', 'unknown').upper()}\n"
            text += f"    Confiance: {detection.get('confidence', 0):.2%}\n"
            text += f"    Contexte: {detection.get('context', 'N/A')}\n"
        
        if additional_info:
            text += "\nℹ️ INFORMATIONS SUPPLÉMENTAIRES\n"
            text += "-" * 30 + "\n"
            for key, value in additional_info.items():
                text += f"{key}: {value}\n"
        
        text += "\n" + "=" * 50 + "\n"
        text += "⚠️ IMPORTANT: Cette alerte a été générée automatiquement.\n"
        text += "🔒 Vérifiez immédiatement ces fuites et prenez les mesures appropriées.\n"
        text += f"🕐 Timestamp: {datetime.now().isoformat()}\n"
        
        return text
    
    def _create_summary_html(self, summary_data: Dict) -> str:
        """Crée le HTML pour le rapport de synthèse"""
        html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2196f3; color: white; padding: 15px; border-radius: 5px; }}
                .summary-box {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .chart {{ margin: 20px 0; }}
                table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>📊 DarkCrawler - Rapport de Synthèse</h1>
                <p>Période: {summary_data.get('period', 'N/A')}</p>
            </div>
            
            <div class="summary-box">
                <h2>📈 Statistiques Générales</h2>
                <p><strong>Total des scans:</strong> {summary_data.get('total_scans', 0)}</p>
                <p><strong>Sites analysés:</strong> {summary_data.get('sites_analyzed', 0)}</p>
                <p><strong>Fuites détectées:</strong> {summary_data.get('total_leaks', 0)}</p>
                <p><strong>Taux de détection:</strong> {summary_data.get('detection_rate', 0):.2%}</p>
            </div>
        </body>
        </html>
        """
        return html
    
    def _create_summary_text(self, summary_data: Dict) -> str:
        """Crée le texte pour le rapport de synthèse"""
        text = "📊 DARKCRAWLER - RAPPORT DE SYNTHÈSE\n"
        text += "=" * 50 + "\n\n"
        text += f"Période: {summary_data.get('period', 'N/A')}\n\n"
        text += "📈 STATISTIQUES GÉNÉRALES\n"
        text += f"Total des scans: {summary_data.get('total_scans', 0)}\n"
        text += f"Sites analysés: {summary_data.get('sites_analyzed', 0)}\n"
        text += f"Fuites détectées: {summary_data.get('total_leaks', 0)}\n"
        text += f"Taux de détection: {summary_data.get('detection_rate', 0):.2%}\n"
        return text
    
    def test_connection(self) -> bool:
        """
        Teste la connexion SMTP
        
        Returns:
            bool: Succès de la connexion
        """
        try:
            context = ssl.create_default_context()
            
            if self.config.use_ssl:
                server = smtplib.SMTP_SSL(self.config.smtp_server, self.config.smtp_port, context=context)
            else:
                server = smtplib.SMTP(self.config.smtp_server, self.config.smtp_port)
                if self.config.use_tls:
                    server.starttls(context=context)
            
            server.login(self.config.username, self.config.password)
            server.quit()
            
            self.logger.info("Test de connexion SMTP réussi")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur test connexion SMTP: {e}")
            return False


def create_email_config_from_env() -> EmailConfig:
    """
    Crée une configuration email depuis les variables d'environnement
    
    Returns:
        EmailConfig: Configuration email
    """
    return EmailConfig(
        smtp_server=os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
        smtp_port=int(os.getenv('SMTP_PORT', '587')),
        username=os.getenv('SMTP_USERNAME', ''),
        password=os.getenv('SMTP_PASSWORD', ''),
        sender_email=os.getenv('SENDER_EMAIL', ''),
        sender_name=os.getenv('SENDER_NAME', 'DarkCrawler Alert System'),
        use_tls=os.getenv('SMTP_USE_TLS', 'true').lower() == 'true',
        use_ssl=os.getenv('SMTP_USE_SSL', 'false').lower() == 'true'
    )


if __name__ == "__main__":
    # Test du module
    logging.basicConfig(level=logging.INFO)
    
    print("📧 Test du module EmailAlertSender")
    
    # Configuration de test (ne pas utiliser en production)
    test_config = EmailConfig(
        smtp_server="smtp.gmail.com",
        smtp_port=587,
        username="test@gmail.com",
        password="test_password",
        sender_email="test@gmail.com",
        sender_name="DarkCrawler Test"
    )
    
    sender = EmailAlertSender(test_config)
    
    # Test de détections
    test_detections = [
        {
            'type': 'email',
            'value': 'admin@company.com',
            'severity': 'medium',
            'confidence': 0.95,
            'context': 'Login: **admin@company.com**'
        },
        {
            'type': 'password',
            'value': 'SuperSecret123',
            'severity': 'critical',
            'confidence': 0.88,
            'context': 'Password: **SuperSecret123**'
        }
    ]
    
    print("✅ Configuration créée")
    print("✅ Détections de test préparées")
    print("ℹ️ Pour tester l'envoi, configurez les variables d'environnement SMTP")