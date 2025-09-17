#!/usr/bin/env python3
"""
Module de génération de rapports pour DarkCrawler
Génère des rapports détaillés des fuites détectées en JSON, Markdown et CSV
"""

import json
import csv
import os
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib

from ..crawler.detector import LeakDetection, SeverityLevel


@dataclass
class ReportMetadata:
    """Métadonnées du rapport"""
    generated_at: str
    crawler_version: str = "1.0.0"
    total_sites_scanned: int = 0
    total_leaks_found: int = 0
    scan_duration: Optional[float] = None
    report_id: str = ""
    
    def __post_init__(self):
        if not self.report_id:
            # Génère un ID unique basé sur le timestamp
            timestamp = datetime.now(timezone.utc).isoformat()
            self.report_id = hashlib.md5(timestamp.encode()).hexdigest()[:8]


@dataclass
class ScanResult:
    """Résultat d'un scan complet"""
    url: str
    scan_timestamp: str
    status: str  # success, error, timeout
    leaks: List[LeakDetection]
    error_message: Optional[str] = None
    response_time: Optional[float] = None
    page_size: Optional[int] = None


class ReportGenerator:
    """Générateur de rapports pour les fuites détectées"""
    
    def __init__(self, output_dir: str = "reports"):
        """
        Initialise le générateur de rapports
        
        Args:
            output_dir: Répertoire de sortie des rapports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Créer les sous-dossiers
        (self.output_dir / "json").mkdir(exist_ok=True)
        (self.output_dir / "markdown").mkdir(exist_ok=True)
        (self.output_dir / "csv").mkdir(exist_ok=True)
    
    def generate_report(self, 
                       scan_results: List[ScanResult], 
                       metadata: ReportMetadata,
                       formats: List[str] = None) -> Dict[str, str]:
        """
        Génère un rapport complet dans les formats spécifiés
        
        Args:
            scan_results: Résultats des scans
            metadata: Métadonnées du rapport
            formats: Formats de sortie ('json', 'markdown', 'csv')
            
        Returns:
            Dict avec les chemins des fichiers générés
        """
        if formats is None:
            formats = ['json', 'markdown', 'csv']
        
        # Mise à jour des métadonnées
        metadata.total_sites_scanned = len(scan_results)
        metadata.total_leaks_found = sum(len(result.leaks) for result in scan_results)
        
        generated_files = {}
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if 'json' in formats:
            json_path = self._generate_json_report(scan_results, metadata, timestamp)
            generated_files['json'] = json_path
        
        if 'markdown' in formats:
            md_path = self._generate_markdown_report(scan_results, metadata, timestamp)
            generated_files['markdown'] = md_path
        
        if 'csv' in formats:
            csv_path = self._generate_csv_report(scan_results, metadata, timestamp)
            generated_files['csv'] = csv_path
        
        return generated_files
    
    def _generate_json_report(self, 
                             scan_results: List[ScanResult], 
                             metadata: ReportMetadata,
                             timestamp: str) -> str:
        """Génère un rapport JSON détaillé"""
        
        # Conversion des résultats en dictionnaires
        results_dict = []
        for result in scan_results:
            result_dict = {
                'url': result.url,
                'scan_timestamp': result.scan_timestamp,
                'status': result.status,
                'response_time': result.response_time,
                'page_size': result.page_size,
                'error_message': result.error_message,
                'leaks': [self._leak_to_dict(leak) for leak in result.leaks]
            }
            results_dict.append(result_dict)
        
        # Statistiques par sévérité
        severity_stats = self._calculate_severity_stats(scan_results)
        
        # Structure du rapport JSON
        report = {
            'metadata': asdict(metadata),
            'statistics': {
                'total_sites_scanned': metadata.total_sites_scanned,
                'total_leaks_found': metadata.total_leaks_found,
                'successful_scans': len([r for r in scan_results if r.status == 'success']),
                'failed_scans': len([r for r in scan_results if r.status != 'success']),
                'severity_breakdown': severity_stats,
                'average_response_time': self._calculate_avg_response_time(scan_results)
            },
            'scan_results': results_dict
        }
        
        # Sauvegarde
        filename = f"darkcrawler_report_{timestamp}.json"
        filepath = self.output_dir / "json" / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)
        
        return str(filepath)
    
    def _generate_markdown_report(self, 
                                 scan_results: List[ScanResult], 
                                 metadata: ReportMetadata,
                                 timestamp: str) -> str:
        """Génère un rapport Markdown lisible"""
        
        severity_stats = self._calculate_severity_stats(scan_results)
        
        md_content = f"""# 🕸️ Rapport DarkCrawler

## 📊 Informations générales

- **ID du rapport**: {metadata.report_id}
- **Généré le**: {metadata.generated_at}
- **Version du crawler**: {metadata.crawler_version}
- **Durée du scan**: {metadata.scan_duration:.2f}s
- **Sites scannés**: {metadata.total_sites_scanned}
- **Fuites détectées**: {metadata.total_leaks_found}

## 📈 Statistiques

### Répartition par sévérité
"""
        
        for severity, count in severity_stats.items():
            emoji = self._get_severity_emoji(severity)
            md_content += f"- {emoji} **{severity.upper()}**: {count} fuites\n"
        
        md_content += f"""
### Performance
- **Scans réussis**: {len([r for r in scan_results if r.status == 'success'])}
- **Scans échoués**: {len([r for r in scan_results if r.status != 'success'])}
- **Temps de réponse moyen**: {self._calculate_avg_response_time(scan_results):.2f}s

## 🔍 Détails des scans

"""
        
        for i, result in enumerate(scan_results, 1):
            md_content += f"### {i}. {result.url}\n\n"
            md_content += f"- **Statut**: {result.status}\n"
            md_content += f"- **Timestamp**: {result.scan_timestamp}\n"
            
            if result.response_time:
                md_content += f"- **Temps de réponse**: {result.response_time:.2f}s\n"
            
            if result.page_size:
                md_content += f"- **Taille de la page**: {result.page_size} bytes\n"
            
            if result.error_message:
                md_content += f"- **Erreur**: {result.error_message}\n"
            
            if result.leaks:
                md_content += f"- **Fuites détectées**: {len(result.leaks)}\n\n"
                
                for j, leak in enumerate(result.leaks, 1):
                    emoji = self._get_severity_emoji(leak.severity.value)
                    md_content += f"  {j}. {emoji} **{leak.leak_type}** ({leak.severity.value})\n"
                    md_content += f"     - Contenu: `{leak.content[:100]}{'...' if len(leak.content) > 100 else ''}`\n"
                    md_content += f"     - Confiance: {leak.confidence:.2f}\n"
                    md_content += f"     - Position: ligne {leak.line_number}\n\n"
            else:
                md_content += "- **Fuites détectées**: Aucune\n\n"
        
        md_content += f"""
---
*Rapport généré par DarkCrawler v{metadata.crawler_version} le {metadata.generated_at}*
"""
        
        # Sauvegarde
        filename = f"darkcrawler_report_{timestamp}.md"
        filepath = self.output_dir / "markdown" / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return str(filepath)
    
    def _generate_csv_report(self, 
                            scan_results: List[ScanResult], 
                            metadata: ReportMetadata,
                            timestamp: str) -> str:
        """Génère un rapport CSV pour analyse"""
        
        filename = f"darkcrawler_report_{timestamp}.csv"
        filepath = self.output_dir / "csv" / filename
        
        with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'report_id', 'url', 'scan_timestamp', 'status', 'response_time',
                'page_size', 'leak_type', 'severity', 'confidence', 'content_preview',
                'line_number', 'context', 'error_message'
            ]
            
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in scan_results:
                if result.leaks:
                    for leak in result.leaks:
                        writer.writerow({
                            'report_id': metadata.report_id,
                            'url': result.url,
                            'scan_timestamp': result.scan_timestamp,
                            'status': result.status,
                            'response_time': result.response_time,
                            'page_size': result.page_size,
                            'leak_type': leak.leak_type,
                            'severity': leak.severity.value,
                            'confidence': leak.confidence,
                            'content_preview': leak.content[:200],
                            'line_number': leak.line_number,
                            'context': leak.context[:100] if leak.context else '',
                            'error_message': result.error_message
                        })
                else:
                    # Ligne pour les scans sans fuites
                    writer.writerow({
                        'report_id': metadata.report_id,
                        'url': result.url,
                        'scan_timestamp': result.scan_timestamp,
                        'status': result.status,
                        'response_time': result.response_time,
                        'page_size': result.page_size,
                        'leak_type': '',
                        'severity': '',
                        'confidence': '',
                        'content_preview': '',
                        'line_number': '',
                        'context': '',
                        'error_message': result.error_message
                    })
        
        return str(filepath)
    
    def _leak_to_dict(self, leak: LeakDetection) -> Dict[str, Any]:
        """Convertit une détection de fuite en dictionnaire"""
        return {
            'leak_type': leak.leak_type,
            'content': leak.content,
            'severity': leak.severity.value,
            'confidence': leak.confidence,
            'line_number': leak.line_number,
            'context': leak.context,
            'timestamp': leak.timestamp,
            'metadata': leak.metadata
        }
    
    def _calculate_severity_stats(self, scan_results: List[ScanResult]) -> Dict[str, int]:
        """Calcule les statistiques par niveau de sévérité"""
        stats = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for result in scan_results:
            for leak in result.leaks:
                stats[leak.severity.value] += 1
        
        return stats
    
    def _calculate_avg_response_time(self, scan_results: List[ScanResult]) -> float:
        """Calcule le temps de réponse moyen"""
        times = [r.response_time for r in scan_results if r.response_time is not None]
        return sum(times) / len(times) if times else 0.0
    
    def _get_severity_emoji(self, severity: str) -> str:
        """Retourne l'emoji correspondant au niveau de sévérité"""
        emojis = {
            'critical': '🚨',
            'high': '⚠️',
            'medium': '⚡',
            'low': '💡',
            'info': 'ℹ️'
        }
        return emojis.get(severity, '❓')
    
    def generate_summary_report(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Génère un résumé rapide des résultats"""
        total_leaks = sum(len(result.leaks) for result in scan_results)
        severity_stats = self._calculate_severity_stats(scan_results)
        
        return {
            'total_sites': len(scan_results),
            'total_leaks': total_leaks,
            'successful_scans': len([r for r in scan_results if r.status == 'success']),
            'failed_scans': len([r for r in scan_results if r.status != 'success']),
            'severity_breakdown': severity_stats,
            'most_critical_sites': [
                result.url for result in scan_results 
                if any(leak.severity == SeverityLevel.CRITICAL for leak in result.leaks)
            ][:5]  # Top 5 sites les plus critiques
        }


# Test du module
if __name__ == "__main__":
    # Test avec des données fictives
    from datetime import datetime, timezone
    
    # Création de données de test
    test_leaks = [
        LeakDetection(
            leak_type="email",
            content="test@example.com",
            severity=SeverityLevel.MEDIUM,
            confidence=0.95,
            line_number=42,
            context="Contact: test@example.com for support"
        ),
        LeakDetection(
            leak_type="password",
            content="password123",
            severity=SeverityLevel.HIGH,
            confidence=0.88,
            line_number=156,
            context="password: password123"
        )
    ]
    
    test_results = [
        ScanResult(
            url="http://example.onion",
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            status="success",
            leaks=test_leaks,
            response_time=2.5,
            page_size=1024
        )
    ]
    
    metadata = ReportMetadata(
        generated_at=datetime.now(timezone.utc).isoformat(),
        scan_duration=10.5
    )
    
    # Test du générateur
    generator = ReportGenerator("test_reports")
    files = generator.generate_report(test_results, metadata)
    
    print("✅ Rapports générés:")
    for format_type, filepath in files.items():
        print(f"  - {format_type.upper()}: {filepath}")
    
    # Test du résumé
    summary = generator.generate_summary_report(test_results)
    print(f"\n📊 Résumé: {summary}")