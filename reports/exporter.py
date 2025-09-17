#!/usr/bin/env python3
"""
Module d'export avancé pour DarkCrawler
Exporte les rapports vers différents formats et services externes
"""

import json
import os
import base64
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Union
from pathlib import Path
import tempfile
import zipfile
import hashlib

try:
    import pdfkit
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

from .generator import ScanResult, ReportMetadata, ReportGenerator


class ReportExporter:
    """Exporteur avancé de rapports avec support multi-format"""
    
    def __init__(self, output_dir: str = "exports"):
        """
        Initialise l'exporteur
        
        Args:
            output_dir: Répertoire de sortie des exports
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Configuration PDF
        self.pdf_options = {
            'page-size': 'A4',
            'margin-top': '0.75in',
            'margin-right': '0.75in',
            'margin-bottom': '0.75in',
            'margin-left': '0.75in',
            'encoding': "UTF-8",
            'no-outline': None,
            'enable-local-file-access': None
        }
    
    def export_to_pdf(self, 
                      markdown_file: str, 
                      output_name: Optional[str] = None) -> str:
        """
        Exporte un rapport Markdown vers PDF
        
        Args:
            markdown_file: Chemin vers le fichier Markdown
            output_name: Nom du fichier de sortie (optionnel)
            
        Returns:
            Chemin vers le fichier PDF généré
        """
        if not PDF_AVAILABLE:
            raise ImportError("pdfkit n'est pas installé. Installez-le avec: pip install pdfkit")
        
        # Lecture du fichier Markdown
        with open(markdown_file, 'r', encoding='utf-8') as f:
            markdown_content = f.read()
        
        # Conversion Markdown vers HTML
        html_content = self._markdown_to_html(markdown_content)
        
        # Nom du fichier de sortie
        if not output_name:
            base_name = Path(markdown_file).stem
            output_name = f"{base_name}.pdf"
        
        output_path = self.output_dir / output_name
        
        # Génération du PDF
        try:
            pdfkit.from_string(html_content, str(output_path), options=self.pdf_options)
            return str(output_path)
        except Exception as e:
            raise RuntimeError(f"Erreur lors de la génération PDF: {e}")
    
    def create_archive(self, 
                      files: List[str], 
                      archive_name: Optional[str] = None,
                      format_type: str = "zip") -> str:
        """
        Crée une archive contenant tous les rapports
        
        Args:
            files: Liste des fichiers à archiver
            archive_name: Nom de l'archive (optionnel)
            format_type: Type d'archive ('zip', 'tar')
            
        Returns:
            Chemin vers l'archive créée
        """
        if not archive_name:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            archive_name = f"darkcrawler_reports_{timestamp}.{format_type}"
        
        archive_path = self.output_dir / archive_name
        
        if format_type == "zip":
            with zipfile.ZipFile(archive_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in files:
                    if os.path.exists(file_path):
                        # Nom du fichier dans l'archive
                        arcname = os.path.basename(file_path)
                        zipf.write(file_path, arcname)
        else:
            raise ValueError(f"Format d'archive non supporté: {format_type}")
        
        return str(archive_path)
    
    def export_to_cloud(self, 
                       file_path: str, 
                       service: str, 
                       config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Exporte un rapport vers un service cloud
        
        Args:
            file_path: Chemin vers le fichier à exporter
            service: Service cloud ('dropbox', 'gdrive', 's3')
            config: Configuration du service
            
        Returns:
            Informations sur l'export
        """
        if not REQUESTS_AVAILABLE:
            raise ImportError("requests n'est pas installé")
        
        if service == "webhook":
            return self._export_to_webhook(file_path, config)
        elif service == "ftp":
            return self._export_to_ftp(file_path, config)
        else:
            raise ValueError(f"Service non supporté: {service}")
    
    def generate_executive_summary(self, 
                                  scan_results: List[ScanResult],
                                  metadata: ReportMetadata) -> str:
        """
        Génère un résumé exécutif en HTML
        
        Args:
            scan_results: Résultats des scans
            metadata: Métadonnées du rapport
            
        Returns:
            Chemin vers le fichier HTML généré
        """
        # Calcul des statistiques
        total_leaks = sum(len(result.leaks) for result in scan_results)
        critical_leaks = sum(
            1 for result in scan_results 
            for leak in result.leaks 
            if leak.severity.value == 'critical'
        )
        
        success_rate = len([r for r in scan_results if r.status == 'success']) / len(scan_results) * 100
        
        # Template HTML
        html_content = f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Résumé Exécutif - DarkCrawler</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            text-align: center;
            margin-bottom: 30px;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .stat-card {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .stat-number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
        }}
        .critical {{
            color: #e74c3c;
        }}
        .success {{
            color: #27ae60;
        }}
        .chart-container {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            margin-bottom: 30px;
        }}
        .recommendations {{
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .recommendation {{
            padding: 10px;
            margin: 10px 0;
            border-left: 4px solid #667eea;
            background-color: #f8f9fa;
        }}
        .footer {{
            text-align: center;
            margin-top: 30px;
            color: #666;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🕸️ DarkCrawler - Résumé Exécutif</h1>
        <p>Rapport généré le {metadata.generated_at}</p>
        <p>ID: {metadata.report_id}</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-number">{metadata.total_sites_scanned}</div>
            <div>Sites Scannés</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{total_leaks}</div>
            <div>Fuites Détectées</div>
        </div>
        <div class="stat-card">
            <div class="stat-number critical">{critical_leaks}</div>
            <div>Fuites Critiques</div>
        </div>
        <div class="stat-card">
            <div class="stat-number success">{success_rate:.1f}%</div>
            <div>Taux de Réussite</div>
        </div>
    </div>
    
    <div class="chart-container">
        <h2>📊 Répartition des Menaces</h2>
        <div id="severity-chart">
            {self._generate_severity_chart(scan_results)}
        </div>
    </div>
    
    <div class="recommendations">
        <h2>💡 Recommandations</h2>
        {self._generate_recommendations(scan_results, critical_leaks)}
    </div>
    
    <div class="footer">
        <p>Généré par DarkCrawler v{metadata.crawler_version}</p>
        <p>⚠️ Ce rapport contient des informations sensibles - À traiter avec précaution</p>
    </div>
</body>
</html>
"""
        
        # Sauvegarde
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"executive_summary_{timestamp}.html"
        filepath = self.output_dir / filename
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    def _markdown_to_html(self, markdown_content: str) -> str:
        """Convertit Markdown en HTML basique"""
        # Conversion basique Markdown -> HTML
        html = markdown_content
        
        # Headers
        html = html.replace('# ', '<h1>').replace('\n', '</h1>\n', 1)
        html = html.replace('## ', '<h2>').replace('\n', '</h2>\n', 1)
        html = html.replace('### ', '<h3>').replace('\n', '</h3>\n', 1)
        
        # Gras et italique
        html = html.replace('**', '<strong>', 1).replace('**', '</strong>', 1)
        html = html.replace('*', '<em>', 1).replace('*', '</em>', 1)
        
        # Listes
        lines = html.split('\n')
        in_list = False
        result_lines = []
        
        for line in lines:
            if line.strip().startswith('- '):
                if not in_list:
                    result_lines.append('<ul>')
                    in_list = True
                result_lines.append(f'<li>{line.strip()[2:]}</li>')
            else:
                if in_list:
                    result_lines.append('</ul>')
                    in_list = False
                result_lines.append(line)
        
        if in_list:
            result_lines.append('</ul>')
        
        # CSS de base
        css = """
        <style>
            body { font-family: Arial, sans-serif; line-height: 1.6; margin: 40px; }
            h1, h2, h3 { color: #333; }
            code { background-color: #f4f4f4; padding: 2px 4px; border-radius: 3px; }
            ul { margin-left: 20px; }
        </style>
        """
        
        return f"<html><head>{css}</head><body>{''.join(result_lines)}</body></html>"
    
    def _export_to_webhook(self, file_path: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Exporte vers un webhook"""
        webhook_url = config.get('url')
        if not webhook_url:
            raise ValueError("URL du webhook manquante")
        
        # Lecture du fichier
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        # Encodage base64 pour l'envoi
        file_b64 = base64.b64encode(file_content).decode('utf-8')
        
        payload = {
            'filename': os.path.basename(file_path),
            'content': file_b64,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'size': len(file_content)
        }
        
        try:
            response = requests.post(webhook_url, json=payload, timeout=30)
            response.raise_for_status()
            
            return {
                'status': 'success',
                'response_code': response.status_code,
                'message': 'Fichier exporté avec succès'
            }
        except requests.RequestException as e:
            return {
                'status': 'error',
                'message': f'Erreur lors de l\'export: {e}'
            }
    
    def _export_to_ftp(self, file_path: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Exporte vers un serveur FTP"""
        try:
            from ftplib import FTP
        except ImportError:
            raise ImportError("Module ftplib non disponible")
        
        host = config.get('host')
        username = config.get('username')
        password = config.get('password')
        remote_path = config.get('remote_path', '/')
        
        if not all([host, username, password]):
            raise ValueError("Configuration FTP incomplète")
        
        try:
            with FTP(host) as ftp:
                ftp.login(username, password)
                ftp.cwd(remote_path)
                
                with open(file_path, 'rb') as f:
                    filename = os.path.basename(file_path)
                    ftp.storbinary(f'STOR {filename}', f)
                
                return {
                    'status': 'success',
                    'message': f'Fichier uploadé vers {host}{remote_path}'
                }
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Erreur FTP: {e}'
            }
    
    def _generate_severity_chart(self, scan_results: List[ScanResult]) -> str:
        """Génère un graphique de sévérité en HTML/CSS"""
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for result in scan_results:
            for leak in result.leaks:
                severity_counts[leak.severity.value] += 1
        
        total = sum(severity_counts.values())
        if total == 0:
            return "<p>Aucune fuite détectée</p>"
        
        colors = {
            'critical': '#e74c3c',
            'high': '#f39c12',
            'medium': '#f1c40f',
            'low': '#3498db',
            'info': '#95a5a6'
        }
        
        chart_html = '<div style="display: flex; height: 30px; border-radius: 15px; overflow: hidden;">'
        
        for severity, count in severity_counts.items():
            if count > 0:
                percentage = (count / total) * 100
                chart_html += f'''
                <div style="
                    background-color: {colors[severity]};
                    width: {percentage}%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    color: white;
                    font-size: 12px;
                    font-weight: bold;
                " title="{severity.upper()}: {count}">
                    {count}
                </div>
                '''
        
        chart_html += '</div>'
        
        # Légende
        legend_html = '<div style="margin-top: 10px; display: flex; flex-wrap: wrap; gap: 15px;">'
        for severity, count in severity_counts.items():
            if count > 0:
                legend_html += f'''
                <div style="display: flex; align-items: center; gap: 5px;">
                    <div style="width: 15px; height: 15px; background-color: {colors[severity]}; border-radius: 3px;"></div>
                    <span>{severity.upper()}: {count}</span>
                </div>
                '''
        legend_html += '</div>'
        
        return chart_html + legend_html
    
    def _generate_recommendations(self, scan_results: List[ScanResult], critical_leaks: int) -> str:
        """Génère des recommandations basées sur les résultats"""
        recommendations = []
        
        if critical_leaks > 0:
            recommendations.append(
                "🚨 <strong>Action immédiate requise</strong>: Des fuites critiques ont été détectées. "
                "Vérifiez immédiatement l'exposition de données sensibles."
            )
        
        failed_scans = len([r for r in scan_results if r.status != 'success'])
        if failed_scans > len(scan_results) * 0.3:  # Plus de 30% d'échecs
            recommendations.append(
                "⚠️ <strong>Problèmes de connectivité</strong>: Un nombre élevé de scans ont échoué. "
                "Vérifiez votre connexion Tor et la disponibilité des sites cibles."
            )
        
        total_leaks = sum(len(result.leaks) for result in scan_results)
        if total_leaks == 0:
            recommendations.append(
                "✅ <strong>Aucune fuite détectée</strong>: Excellent! Continuez la surveillance régulière "
                "pour maintenir ce niveau de sécurité."
            )
        
        recommendations.append(
            "📊 <strong>Surveillance continue</strong>: Planifiez des scans réguliers pour détecter "
            "de nouvelles fuites potentielles."
        )
        
        html = ""
        for rec in recommendations:
            html += f'<div class="recommendation">{rec}</div>'
        
        return html


# Test du module
if __name__ == "__main__":
    # Test avec des données fictives
    from .generator import ScanResult, ReportMetadata, LeakDetection, SeverityLevel
    from datetime import datetime, timezone
    
    # Données de test
    test_leaks = [
        LeakDetection(
            leak_type="email",
            content="admin@company.com",
            severity=SeverityLevel.HIGH,
            confidence=0.95,
            line_number=42
        )
    ]
    
    test_results = [
        ScanResult(
            url="http://test.onion",
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            status="success",
            leaks=test_leaks,
            response_time=1.5,
            page_size=2048
        )
    ]
    
    metadata = ReportMetadata(
        generated_at=datetime.now(timezone.utc).isoformat(),
        scan_duration=5.0
    )
    
    # Test de l'exporteur
    exporter = ReportExporter("test_exports")
    
    # Génération du résumé exécutif
    summary_path = exporter.generate_executive_summary(test_results, metadata)
    print(f"✅ Résumé exécutif généré: {summary_path}")
    
    # Test d'archive
    files_to_archive = [summary_path]
    archive_path = exporter.create_archive(files_to_archive)
    print(f"✅ Archive créée: {archive_path}")
    
    print("🎉 Tests d'export terminés avec succès!")