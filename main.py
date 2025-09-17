#!/usr/bin/env python3
"""
DarkCrawler - Détecteur de fuites sur le Dark Web
Crawler intelligent pour détecter des fuites de données sensibles via Tor

Auteur: JimmyRamsamynaick
Email: jimmyramsamynaick@gmail.com
Version: 1.0.0
"""

import asyncio
import argparse
import json
import sys
import time
import signal
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin, urlparse
import logging

# Imports des modules DarkCrawler
from crawler.tor_session import TorSession, check_tor_installation, start_tor_if_needed
from crawler.parser import WebParser
from crawler.detector import DataLeakDetector, SeverityLevel
from alerts.email import EmailAlertSender
from alerts.webhook import WebhookAlertSender, WebhookType
from alerts.logger import logger, AlertLevel
from reports.generator import ReportGenerator, ScanResult, ReportMetadata
from reports.exporter import ReportExporter


class DarkCrawlerConfig:
    """Configuration du crawler"""
    
    def __init__(self, config_file: str = "config/crawler_config.json"):
        """
        Initialise la configuration
        
        Args:
            config_file: Chemin vers le fichier de configuration
        """
        self.config_file = Path(config_file)
        self.config = self._load_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Charge la configuration depuis le fichier JSON"""
        default_config = {
            "crawler": {
                "max_pages": 10,
                "delay_between_requests": 2.0,
                "timeout": 30,
                "max_retries": 3,
                "user_agents": [
                    "Mozilla/5.0 (Windows NT 10.0; rv:91.0) Gecko/20100101 Firefox/91.0",
                    "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0"
                ],
                "respect_robots_txt": True
            },
            "detection": {
                "keywords_file": "config/keywords.json",
                "min_confidence": 0.7,
                "max_content_length": 1000000  # 1MB
            },
            "alerts": {
                "email": {
                    "enabled": False,
                    "smtp_server": "",
                    "smtp_port": 587,
                    "username": "",
                    "password": "",
                    "recipients": []
                },
                "webhook": {
                    "enabled": False,
                    "url": "",
                    "type": "slack"
                },
                "console": {
                    "enabled": True,
                    "min_severity": "medium"
                }
            },
            "reports": {
                "formats": ["json", "markdown", "csv"],
                "output_dir": "reports",
                "auto_export": {
                    "enabled": False,
                    "archive": True,
                    "cloud_upload": False
                }
            },
            "tor": {
                "proxy_host": "127.0.0.1",
                "proxy_port": 9050,
                "control_port": 9051,
                "auto_start": True,
                "new_identity_interval": 300  # 5 minutes
            }
        }
        
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    user_config = json.load(f)
                    # Fusion des configurations
                    self._merge_config(default_config, user_config)
            except Exception as e:
                logger.warning(f"Erreur lors du chargement de la config: {e}")
        else:
            # Créer le fichier de configuration par défaut
            self.config_file.parent.mkdir(exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(default_config, f, indent=2)
            logger.info(f"Configuration par défaut créée: {self.config_file}")
        
        return default_config
    
    def _merge_config(self, default: Dict, user: Dict) -> None:
        """Fusionne la configuration utilisateur avec la configuration par défaut"""
        for key, value in user.items():
            if key in default:
                if isinstance(value, dict) and isinstance(default[key], dict):
                    self._merge_config(default[key], value)
                else:
                    default[key] = value
            else:
                default[key] = value


class DarkCrawler:
    """Crawler principal pour le Dark Web"""
    
    def __init__(self, config: DarkCrawlerConfig):
        """
        Initialise le crawler
        
        Args:
            config: Configuration du crawler
        """
        self.config = config.config
        self.running = False
        self.scan_results: List[ScanResult] = []
        
        # Initialisation des composants
        self.tor_session = None
        self.parser = WebParser()
        self.detector = DataLeakDetector()
        self.email_sender = None
        self.webhook_sender = None
        self.report_generator = ReportGenerator(self.config['reports']['output_dir'])
        self.report_exporter = ReportExporter()
        
        # Statistiques
        self.stats = {
            'start_time': None,
            'sites_scanned': 0,
            'leaks_found': 0,
            'errors': 0
        }
        
        # Gestion des signaux
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Gestionnaire de signaux pour arrêt propre"""
        logger.info(f"Signal {signum} reçu, arrêt en cours...")
        self.running = False
    
    async def initialize(self) -> bool:
        """
        Initialise tous les composants du crawler
        
        Returns:
            True si l'initialisation réussit
        """
        try:
            logger.info("🚀 Initialisation de DarkCrawler...")
            
            # Vérification de Tor
            if not check_tor_installation():
                logger.error("Tor n'est pas installé ou accessible")
                return False
            
            # Démarrage automatique de Tor si configuré
            if self.config['tor']['auto_start']:
                if not start_tor_if_needed():
                    logger.warning("Impossible de démarrer Tor automatiquement")
            
            # Initialisation de la session Tor
            self.tor_session = TorSession(
                proxy_host=self.config['tor']['proxy_host'],
                proxy_port=self.config['tor']['proxy_port']
            )
            
            if not await self.tor_session.create_session():
                logger.error("Impossible de créer la session Tor")
                return False
            
            # Test de connectivité
            if not await self.tor_session.test_connectivity():
                logger.error("Test de connectivité Tor échoué")
                return False
            
            # Initialisation des alertes
            await self._initialize_alerts()
            
            logger.info("✅ DarkCrawler initialisé avec succès")
            return True
            
        except Exception as e:
            logger.error(f"Erreur lors de l'initialisation: {e}")
            return False
    
    async def _initialize_alerts(self):
        """Initialise les systèmes d'alerte"""
        # Email
        if self.config['alerts']['email']['enabled']:
            self.email_sender = EmailAlertSender(
                smtp_server=self.config['alerts']['email']['smtp_server'],
                smtp_port=self.config['alerts']['email']['smtp_port'],
                username=self.config['alerts']['email']['username'],
                password=self.config['alerts']['email']['password']
            )
        
        # Webhook
        if self.config['alerts']['webhook']['enabled']:
            webhook_type = WebhookType(self.config['alerts']['webhook']['type'])
            self.webhook_sender = WebhookAlertSender(
                webhook_url=self.config['alerts']['webhook']['url'],
                webhook_type=webhook_type
            )
    
    async def scan_url(self, url: str) -> ScanResult:
        """
        Scanne une URL spécifique
        
        Args:
            url: URL à scanner
            
        Returns:
            Résultat du scan
        """
        start_time = time.time()
        scan_timestamp = datetime.now(timezone.utc).isoformat()
        
        try:
            logger.info(f"🔍 Scan de {url}")
            
            # Requête via Tor
            response = await self.tor_session.safe_request(url)
            if not response:
                return ScanResult(
                    url=url,
                    scan_timestamp=scan_timestamp,
                    status="error",
                    leaks=[],
                    error_message="Impossible de récupérer la page",
                    response_time=time.time() - start_time
                )
            
            # Parsing du contenu
            parsed_data = self.parser.parse_html(response.text, url)
            
            # Détection de fuites
            leaks = []
            
            # Analyse du texte principal
            text_leaks = self.detector.detect_leaks(parsed_data['text'])
            leaks.extend(text_leaks)
            
            # Analyse des commentaires HTML
            for comment in parsed_data['comments']:
                comment_leaks = self.detector.detect_leaks(comment)
                leaks.extend(comment_leaks)
            
            # Analyse des scripts
            for script in parsed_data['scripts']:
                script_leaks = self.detector.detect_leaks(script)
                leaks.extend(script_leaks)
            
            # Filtrage par confiance
            min_confidence = self.config['detection']['min_confidence']
            filtered_leaks = [leak for leak in leaks if leak.confidence >= min_confidence]
            
            # Envoi d'alertes si nécessaire
            if filtered_leaks:
                await self._send_alerts(url, filtered_leaks)
            
            response_time = time.time() - start_time
            
            return ScanResult(
                url=url,
                scan_timestamp=scan_timestamp,
                status="success",
                leaks=filtered_leaks,
                response_time=response_time,
                page_size=len(response.content) if hasattr(response, 'content') else len(response.text)
            )
            
        except Exception as e:
            logger.error(f"Erreur lors du scan de {url}: {e}")
            return ScanResult(
                url=url,
                scan_timestamp=scan_timestamp,
                status="error",
                leaks=[],
                error_message=str(e),
                response_time=time.time() - start_time
            )
    
    async def _send_alerts(self, url: str, leaks: List):
        """Envoie les alertes pour les fuites détectées"""
        try:
            # Alerte console
            if self.config['alerts']['console']['enabled']:
                min_severity = self.config['alerts']['console']['min_severity']
                for leak in leaks:
                    if self._should_alert(leak.severity.value, min_severity):
                        logger.alert(f"🚨 Fuite détectée sur {url}: {leak.type} - {leak.value[:50]}...")
            
            # Alerte email
            if self.email_sender and leaks:
                critical_leaks = [l for l in leaks if l.severity == SeverityLevel.CRITICAL]
                if critical_leaks:
                    await self.email_sender.send_leak_alert(
                        url, critical_leaks, self.config['alerts']['email']['recipients']
                    )
            
            # Alerte webhook
            if self.webhook_sender and leaks:
                high_priority_leaks = [
                    l for l in leaks 
                    if l.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
                ]
                if high_priority_leaks:
                    await self.webhook_sender.send_leak_alert(url, high_priority_leaks)
                    
        except Exception as e:
            logger.error(f"Erreur lors de l'envoi d'alertes: {e}")
    
    def _should_alert(self, severity: str, min_severity: str) -> bool:
        """Détermine si une alerte doit être envoyée"""
        severity_levels = ['info', 'low', 'medium', 'high', 'critical']
        return severity_levels.index(severity) >= severity_levels.index(min_severity)
    
    async def scan_urls(self, urls: List[str]) -> List[ScanResult]:
        """
        Scanne une liste d'URLs
        
        Args:
            urls: Liste des URLs à scanner
            
        Returns:
            Liste des résultats de scan
        """
        self.running = True
        self.stats['start_time'] = time.time()
        results = []
        
        logger.info(f"🎯 Début du scan de {len(urls)} URLs")
        
        for i, url in enumerate(urls, 1):
            if not self.running:
                logger.info("Arrêt demandé, interruption du scan")
                break
            
            logger.info(f"📍 Progression: {i}/{len(urls)} - {url}")
            
            # Scan de l'URL
            result = await self.scan_url(url)
            results.append(result)
            
            # Mise à jour des statistiques
            self.stats['sites_scanned'] += 1
            if result.status == "success":
                self.stats['leaks_found'] += len(result.leaks)
            else:
                self.stats['errors'] += 1
            
            # Délai entre les requêtes
            if i < len(urls):  # Pas de délai après la dernière requête
                delay = self.config['crawler']['delay_between_requests']
                logger.debug(f"⏳ Attente de {delay}s avant la prochaine requête")
                await asyncio.sleep(delay)
            
            # Changement d'identité Tor périodique
            if i % 10 == 0:  # Tous les 10 scans
                logger.info("🔄 Changement d'identité Tor")
                await self.tor_session.new_identity()
                await asyncio.sleep(5)  # Attente pour la nouvelle identité
        
        self.scan_results = results
        return results
    
    async def generate_reports(self, scan_results: List[ScanResult]) -> Dict[str, str]:
        """
        Génère les rapports de scan
        
        Args:
            scan_results: Résultats des scans
            
        Returns:
            Dictionnaire des fichiers générés
        """
        try:
            logger.info("📊 Génération des rapports...")
            
            # Métadonnées du rapport
            metadata = ReportMetadata(
                generated_at=datetime.now(timezone.utc).isoformat(),
                total_sites_scanned=len(scan_results),
                scan_duration=time.time() - self.stats['start_time'] if self.stats['start_time'] else 0
            )
            
            # Génération des rapports
            formats = self.config['reports']['formats']
            generated_files = self.report_generator.generate_report(
                scan_results, metadata, formats
            )
            
            # Export automatique si configuré
            if self.config['reports']['auto_export']['enabled']:
                await self._auto_export_reports(generated_files, scan_results, metadata)
            
            return generated_files
            
        except Exception as e:
            logger.error(f"Erreur lors de la génération des rapports: {e}")
            return {}
    
    async def _auto_export_reports(self, 
                                  generated_files: Dict[str, str],
                                  scan_results: List[ScanResult],
                                  metadata: ReportMetadata):
        """Export automatique des rapports"""
        try:
            # Génération du résumé exécutif
            summary_path = self.report_exporter.generate_executive_summary(
                scan_results, metadata
            )
            generated_files['executive_summary'] = summary_path
            
            # Création d'archive si configuré
            if self.config['reports']['auto_export']['archive']:
                archive_path = self.report_exporter.create_archive(
                    list(generated_files.values())
                )
                logger.info(f"📦 Archive créée: {archive_path}")
            
        except Exception as e:
            logger.error(f"Erreur lors de l'export automatique: {e}")
    
    async def cleanup(self):
        """Nettoyage des ressources"""
        try:
            if self.tor_session:
                await self.tor_session.close()
            logger.info("🧹 Nettoyage terminé")
        except Exception as e:
            logger.error(f"Erreur lors du nettoyage: {e}")
    
    def print_stats(self):
        """Affiche les statistiques finales"""
        if self.stats['start_time']:
            duration = time.time() - self.stats['start_time']
            logger.info("📈 Statistiques finales:")
            logger.info(f"  • Durée totale: {duration:.2f}s")
            logger.info(f"  • Sites scannés: {self.stats['sites_scanned']}")
            logger.info(f"  • Fuites trouvées: {self.stats['leaks_found']}")
            logger.info(f"  • Erreurs: {self.stats['errors']}")
            
            if self.stats['sites_scanned'] > 0:
                success_rate = ((self.stats['sites_scanned'] - self.stats['errors']) / 
                              self.stats['sites_scanned']) * 100
                logger.info(f"  • Taux de réussite: {success_rate:.1f}%")


async def main():
    """Fonction principale"""
    parser = argparse.ArgumentParser(
        description="DarkCrawler - Détecteur de fuites sur le Dark Web",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python main.py --urls http://example.onion
  python main.py --file urls.txt --config config/custom.json
  python main.py --urls http://site1.onion http://site2.onion --formats json markdown
        """
    )
    
    parser.add_argument(
        '--urls', 
        nargs='+', 
        help='URLs à scanner'
    )
    
    parser.add_argument(
        '--file', 
        help='Fichier contenant les URLs à scanner (une par ligne)'
    )
    
    parser.add_argument(
        '--config', 
        default='config/crawler_config.json',
        help='Fichier de configuration (défaut: config/crawler_config.json)'
    )
    
    parser.add_argument(
        '--formats', 
        nargs='+', 
        choices=['json', 'markdown', 'csv'],
        help='Formats de rapport à générer'
    )
    
    parser.add_argument(
        '--output-dir', 
        help='Répertoire de sortie des rapports'
    )
    
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true',
        help='Mode verbeux'
    )
    
    parser.add_argument(
        '--version', 
        action='version', 
        version='DarkCrawler 1.0.0'
    )
    
    args = parser.parse_args()
    
    # Configuration du logging
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Chargement de la configuration
    try:
        config = DarkCrawlerConfig(args.config)
    except Exception as e:
        logger.error(f"Erreur de configuration: {e}")
        sys.exit(1)
    
    # Override des paramètres de configuration
    if args.formats:
        config.config['reports']['formats'] = args.formats
    
    if args.output_dir:
        config.config['reports']['output_dir'] = args.output_dir
    
    # Récupération des URLs
    urls = []
    
    if args.urls:
        urls.extend(args.urls)
    
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                file_urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                urls.extend(file_urls)
        except Exception as e:
            logger.error(f"Erreur lors de la lecture du fichier {args.file}: {e}")
            sys.exit(1)
    
    if not urls:
        logger.error("Aucune URL à scanner. Utilisez --urls ou --file")
        sys.exit(1)
    
    # Validation des URLs .onion
    valid_urls = []
    for url in urls:
        if '.onion' in url or url.startswith('http://') or url.startswith('https://'):
            valid_urls.append(url)
        else:
            logger.warning(f"URL ignorée (non .onion): {url}")
    
    if not valid_urls:
        logger.error("Aucune URL valide à scanner")
        sys.exit(1)
    
    # Initialisation et exécution du crawler
    crawler = DarkCrawler(config)
    
    try:
        # Initialisation
        if not await crawler.initialize():
            logger.error("Échec de l'initialisation")
            sys.exit(1)
        
        # Scan des URLs
        logger.info(f"🎯 Début du scan de {len(valid_urls)} URLs")
        results = await crawler.scan_urls(valid_urls)
        
        # Génération des rapports
        generated_files = await crawler.generate_reports(results)
        
        # Affichage des résultats
        crawler.print_stats()
        
        if generated_files:
            logger.info("📄 Rapports générés:")
            for format_type, filepath in generated_files.items():
                logger.info(f"  • {format_type.upper()}: {filepath}")
        
        logger.info("✅ Scan terminé avec succès!")
        
    except KeyboardInterrupt:
        logger.info("⏹️ Arrêt demandé par l'utilisateur")
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        sys.exit(1)
    finally:
        await crawler.cleanup()


if __name__ == "__main__":
    # Vérification de la version Python
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ requis")
        sys.exit(1)
    
    # Exécution du programme principal
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n⏹️ Programme interrompu")
        sys.exit(0)