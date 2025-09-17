"""
Module de logging pour DarkCrawler
Gère les logs avec différents niveaux de sévérité et formatage
"""

import logging
import logging.handlers
import json
import os
from typing import Dict, List, Optional, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path


class AlertLevel(Enum):
    """Niveaux d'alerte"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


@dataclass
class LogEntry:
    """Entrée de log structurée"""
    timestamp: datetime
    level: AlertLevel
    message: str
    source: str
    details: Dict[str, Any] = None
    detection_count: int = 0
    source_url: str = ""
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}
    
    def to_dict(self) -> Dict:
        """Convertit l'entrée en dictionnaire"""
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        data['level'] = self.level.value
        return data
    
    def to_json(self) -> str:
        """Convertit l'entrée en JSON"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)


class ColoredFormatter(logging.Formatter):
    """Formateur avec couleurs pour la console"""
    
    # Codes couleur ANSI
    COLORS = {
        'DEBUG': '\033[36m',      # Cyan
        'INFO': '\033[32m',       # Vert
        'WARNING': '\033[33m',    # Jaune
        'ERROR': '\033[31m',      # Rouge
        'CRITICAL': '\033[35m',   # Magenta
        'RESET': '\033[0m'        # Reset
    }
    
    def format(self, record):
        # Ajouter la couleur
        color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # Formater le message
        formatted = super().format(record)
        
        return f"{color}{formatted}{reset}"


class JSONFormatter(logging.Formatter):
    """Formateur JSON pour les logs structurés"""
    
    def format(self, record):
        log_entry = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname.lower(),
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Ajouter les attributs personnalisés
        if hasattr(record, 'detection_count'):
            log_entry['detection_count'] = record.detection_count
        
        if hasattr(record, 'source_url'):
            log_entry['source_url'] = record.source_url
        
        if hasattr(record, 'details'):
            log_entry['details'] = record.details
        
        return json.dumps(log_entry, ensure_ascii=False)


class DarkCrawlerLogger:
    """Logger principal pour DarkCrawler"""
    
    def __init__(self, name: str = "darkcrawler", log_dir: str = "logs"):
        """
        Initialise le logger
        
        Args:
            name: Nom du logger
            log_dir: Répertoire des logs
        """
        self.name = name
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(exist_ok=True)
        
        # Créer le logger principal
        self.logger = logging.getLogger(name)
        self.logger.setLevel(logging.DEBUG)
        
        # Éviter la duplication des handlers
        if not self.logger.handlers:
            self._setup_handlers()
        
        # Historique des alertes
        self.alert_history: List[LogEntry] = []
        self.max_history = 1000
    
    def _setup_handlers(self):
        """Configure les handlers de logging"""
        
        # Handler console avec couleurs
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_formatter = ColoredFormatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
            datefmt='%H:%M:%S'
        )
        console_handler.setFormatter(console_formatter)
        self.logger.addHandler(console_handler)
        
        # Handler fichier général
        general_log = self.log_dir / "darkcrawler.log"
        file_handler = logging.handlers.RotatingFileHandler(
            general_log,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(
            '%(asctime)s | %(levelname)-8s | %(name)s | %(funcName)s:%(lineno)d | %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Handler fichier JSON pour les alertes
        alerts_log = self.log_dir / "alerts.jsonl"
        json_handler = logging.handlers.RotatingFileHandler(
            alerts_log,
            maxBytes=50*1024*1024,  # 50MB
            backupCount=10,
            encoding='utf-8'
        )
        json_handler.setLevel(logging.WARNING)
        json_formatter = JSONFormatter()
        json_handler.setFormatter(json_formatter)
        self.logger.addHandler(json_handler)
        
        # Handler fichier pour les erreurs uniquement
        error_log = self.log_dir / "errors.log"
        error_handler = logging.handlers.RotatingFileHandler(
            error_log,
            maxBytes=5*1024*1024,  # 5MB
            backupCount=3,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(file_formatter)
        self.logger.addHandler(error_handler)
    
    def log_detection_alert(self, detections: List[Dict], source_url: str = "", 
                           additional_info: Dict = None):
        """
        Log une alerte de détection
        
        Args:
            detections: Liste des détections
            source_url: URL source
            additional_info: Informations supplémentaires
        """
        detection_count = len(detections)
        
        # Déterminer le niveau selon la sévérité
        max_severity = self._get_max_severity(detections)
        level_map = {
            'critical': AlertLevel.CRITICAL,
            'high': AlertLevel.ERROR,
            'medium': AlertLevel.WARNING,
            'low': AlertLevel.INFO
        }
        alert_level = level_map.get(max_severity, AlertLevel.INFO)
        
        # Créer le message
        message = f"🚨 {detection_count} fuite(s) détectée(s)"
        if source_url:
            domain = source_url.split('/')[2] if '/' in source_url else source_url
            message += f" sur {domain}"
        
        # Détails pour le log structuré
        details = {
            'detections': detections,
            'max_severity': max_severity,
            'detection_types': list(set(d.get('type', 'unknown') for d in detections)),
            'high_confidence_count': len([d for d in detections if d.get('confidence', 0) >= 0.8])
        }
        
        if additional_info:
            details.update(additional_info)
        
        # Logger avec les détails
        log_level = getattr(logging, alert_level.value.upper())
        self.logger.log(
            log_level,
            message,
            extra={
                'detection_count': detection_count,
                'source_url': source_url,
                'details': details
            }
        )
        
        # Ajouter à l'historique
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=alert_level,
            message=message,
            source=source_url,
            details=details,
            detection_count=detection_count,
            source_url=source_url
        )
        
        self._add_to_history(log_entry)
        
        # Log détaillé des détections critiques
        critical_detections = [d for d in detections if d.get('severity') == 'critical']
        if critical_detections:
            for detection in critical_detections:
                self.logger.critical(
                    f"🔴 CRITIQUE: {detection.get('type', 'Unknown')} - {detection.get('value', 'N/A')}",
                    extra={
                        'detection_count': 1,
                        'source_url': source_url,
                        'details': detection
                    }
                )
    
    def log_scan_start(self, target_url: str, scan_config: Dict = None):
        """
        Log le début d'un scan
        
        Args:
            target_url: URL cible
            scan_config: Configuration du scan
        """
        message = f"🔍 Début du scan: {target_url}"
        
        details = {'scan_config': scan_config} if scan_config else {}
        
        self.logger.info(
            message,
            extra={
                'source_url': target_url,
                'details': details
            }
        )
        
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=AlertLevel.INFO,
            message=message,
            source=target_url,
            details=details,
            source_url=target_url
        )
        
        self._add_to_history(log_entry)
    
    def log_scan_complete(self, target_url: str, stats: Dict):
        """
        Log la fin d'un scan
        
        Args:
            target_url: URL cible
            stats: Statistiques du scan
        """
        duration = stats.get('duration', 0)
        pages_scanned = stats.get('pages_scanned', 0)
        detections_found = stats.get('detections_found', 0)
        
        message = f"✅ Scan terminé: {target_url} ({duration:.2f}s, {pages_scanned} pages, {detections_found} détections)"
        
        self.logger.info(
            message,
            extra={
                'source_url': target_url,
                'details': stats
            }
        )
        
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=AlertLevel.INFO,
            message=message,
            source=target_url,
            details=stats,
            detection_count=detections_found,
            source_url=target_url
        )
        
        self._add_to_history(log_entry)
    
    def log_error(self, error_message: str, source: str = "", 
                  exception: Exception = None, details: Dict = None):
        """
        Log une erreur
        
        Args:
            error_message: Message d'erreur
            source: Source de l'erreur
            exception: Exception si disponible
            details: Détails supplémentaires
        """
        if exception:
            message = f"❌ {error_message}: {str(exception)}"
        else:
            message = f"❌ {error_message}"
        
        log_details = details or {}
        if exception:
            log_details['exception_type'] = type(exception).__name__
            log_details['exception_message'] = str(exception)
        
        self.logger.error(
            message,
            extra={
                'source_url': source,
                'details': log_details
            },
            exc_info=exception is not None
        )
        
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=AlertLevel.ERROR,
            message=message,
            source=source,
            details=log_details,
            source_url=source
        )
        
        self._add_to_history(log_entry)
    
    def log_warning(self, warning_message: str, source: str = "", 
                   details: Dict = None):
        """
        Log un avertissement
        
        Args:
            warning_message: Message d'avertissement
            source: Source de l'avertissement
            details: Détails supplémentaires
        """
        message = f"⚠️ {warning_message}"
        
        self.logger.warning(
            message,
            extra={
                'source_url': source,
                'details': details or {}
            }
        )
        
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=AlertLevel.WARNING,
            message=message,
            source=source,
            details=details or {},
            source_url=source
        )
        
        self._add_to_history(log_entry)
    
    def log_info(self, info_message: str, source: str = "", 
                details: Dict = None):
        """
        Log une information
        
        Args:
            info_message: Message d'information
            source: Source de l'information
            details: Détails supplémentaires
        """
        message = f"ℹ️ {info_message}"
        
        self.logger.info(
            message,
            extra={
                'source_url': source,
                'details': details or {}
            }
        )
        
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=AlertLevel.INFO,
            message=message,
            source=source,
            details=details or {},
            source_url=source
        )
        
        self._add_to_history(log_entry)
    
    def log_debug(self, debug_message: str, source: str = "", 
                 details: Dict = None):
        """
        Log un message de debug
        
        Args:
            debug_message: Message de debug
            source: Source du debug
            details: Détails supplémentaires
        """
        message = f"🔧 {debug_message}"
        
        self.logger.debug(
            message,
            extra={
                'source_url': source,
                'details': details or {}
            }
        )
        
        log_entry = LogEntry(
            timestamp=datetime.now(),
            level=AlertLevel.DEBUG,
            message=message,
            source=source,
            details=details or {},
            source_url=source
        )
        
        self._add_to_history(log_entry)
    
    def get_recent_alerts(self, count: int = 50, 
                         level: AlertLevel = None) -> List[LogEntry]:
        """
        Récupère les alertes récentes
        
        Args:
            count: Nombre d'alertes à récupérer
            level: Niveau minimum (optionnel)
            
        Returns:
            List[LogEntry]: Liste des alertes récentes
        """
        alerts = self.alert_history
        
        if level:
            level_order = {
                AlertLevel.DEBUG: 0,
                AlertLevel.INFO: 1,
                AlertLevel.WARNING: 2,
                AlertLevel.ERROR: 3,
                AlertLevel.CRITICAL: 4
            }
            min_level = level_order[level]
            alerts = [a for a in alerts if level_order[a.level] >= min_level]
        
        return alerts[-count:] if count > 0 else alerts
    
    def get_statistics(self, hours: int = 24) -> Dict:
        """
        Génère des statistiques sur les logs
        
        Args:
            hours: Nombre d'heures à analyser
            
        Returns:
            Dict: Statistiques
        """
        cutoff_time = datetime.now().timestamp() - (hours * 3600)
        recent_alerts = [
            a for a in self.alert_history 
            if a.timestamp.timestamp() > cutoff_time
        ]
        
        stats = {
            'total_alerts': len(recent_alerts),
            'by_level': {},
            'total_detections': 0,
            'unique_sources': set(),
            'most_active_sources': {},
            'detection_types': {}
        }
        
        for alert in recent_alerts:
            # Par niveau
            level = alert.level.value
            stats['by_level'][level] = stats['by_level'].get(level, 0) + 1
            
            # Détections
            stats['total_detections'] += alert.detection_count
            
            # Sources
            if alert.source_url:
                stats['unique_sources'].add(alert.source_url)
                stats['most_active_sources'][alert.source_url] = \
                    stats['most_active_sources'].get(alert.source_url, 0) + 1
            
            # Types de détection
            if alert.details and 'detection_types' in alert.details:
                for det_type in alert.details['detection_types']:
                    stats['detection_types'][det_type] = \
                        stats['detection_types'].get(det_type, 0) + 1
        
        stats['unique_sources'] = len(stats['unique_sources'])
        
        # Top 5 des sources les plus actives
        stats['top_sources'] = sorted(
            stats['most_active_sources'].items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]
        
        return stats
    
    def export_logs(self, output_file: str, format: str = "json", 
                   hours: int = 24) -> bool:
        """
        Exporte les logs
        
        Args:
            output_file: Fichier de sortie
            format: Format (json, csv, txt)
            hours: Nombre d'heures à exporter
            
        Returns:
            bool: Succès de l'export
        """
        try:
            cutoff_time = datetime.now().timestamp() - (hours * 3600)
            recent_alerts = [
                a for a in self.alert_history 
                if a.timestamp.timestamp() > cutoff_time
            ]
            
            if format.lower() == "json":
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(
                        [alert.to_dict() for alert in recent_alerts],
                        f,
                        ensure_ascii=False,
                        indent=2
                    )
            
            elif format.lower() == "csv":
                import csv
                with open(output_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['timestamp', 'level', 'message', 'source', 'detection_count'])
                    
                    for alert in recent_alerts:
                        writer.writerow([
                            alert.timestamp.isoformat(),
                            alert.level.value,
                            alert.message,
                            alert.source,
                            alert.detection_count
                        ])
            
            elif format.lower() == "txt":
                with open(output_file, 'w', encoding='utf-8') as f:
                    for alert in recent_alerts:
                        f.write(f"{alert.timestamp.isoformat()} | {alert.level.value.upper()} | {alert.message}\n")
            
            self.logger.info(f"Logs exportés vers {output_file} ({len(recent_alerts)} entrées)")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur export logs: {e}")
            return False
    
    def _get_max_severity(self, detections: List[Dict]) -> str:
        """Détermine la sévérité maximale"""
        severity_order = ['critical', 'high', 'medium', 'low']
        
        for severity in severity_order:
            if any(d.get('severity') == severity for d in detections):
                return severity
        
        return 'low'
    
    def _add_to_history(self, log_entry: LogEntry):
        """Ajoute une entrée à l'historique"""
        self.alert_history.append(log_entry)
        
        # Limiter la taille de l'historique
        if len(self.alert_history) > self.max_history:
            self.alert_history = self.alert_history[-self.max_history:]
    
    def set_level(self, level: str):
        """
        Définit le niveau de logging
        
        Args:
            level: Niveau (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        """
        numeric_level = getattr(logging, level.upper(), logging.INFO)
        self.logger.setLevel(numeric_level)
        
        # Mettre à jour le handler console
        for handler in self.logger.handlers:
            if isinstance(handler, logging.StreamHandler) and not isinstance(handler, logging.FileHandler):
                handler.setLevel(numeric_level)


# Instance globale du logger
darkcrawler_logger = DarkCrawlerLogger()


if __name__ == "__main__":
    # Test du module
    print("📝 Test du module DarkCrawlerLogger")
    
    logger = DarkCrawlerLogger("test_logger")
    
    # Test des différents niveaux
    logger.log_info("Test d'information", "test_source")
    logger.log_warning("Test d'avertissement", "test_source")
    logger.log_error("Test d'erreur", "test_source")
    
    # Test d'alerte de détection
    test_detections = [
        {
            'type': 'email',
            'value': 'test@example.com',
            'severity': 'medium',
            'confidence': 0.95
        },
        {
            'type': 'password',
            'value': 'secret123',
            'severity': 'critical',
            'confidence': 0.88
        }
    ]
    
    logger.log_detection_alert(test_detections, "http://test.onion")
    
    # Statistiques
    stats = logger.get_statistics(1)
    print(f"✅ Statistiques: {stats}")
    
    # Alertes récentes
    recent = logger.get_recent_alerts(10)
    print(f"✅ Alertes récentes: {len(recent)}")
    
    print("✅ Test terminé - Vérifiez le dossier 'logs' pour les fichiers générés")