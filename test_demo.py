#!/usr/bin/env python3
"""
Script de démonstration DarkCrawler
Teste les fonctionnalités sans nécessiter Tor
"""

import asyncio
import json
from pathlib import Path
from datetime import datetime

# Import des modules DarkCrawler
from crawler.detector import DataLeakDetector, LeakDetection, SeverityLevel
from alerts.logger import logger, AlertLevel
from reports.generator import ReportGenerator, ScanResult, ReportMetadata


async def demo_detection():
    """Démonstration du système de détection"""
    print("🔍 === DÉMONSTRATION DU DÉTECTEUR DE FUITES ===")
    
    # Initialiser le détecteur
    detector = DataLeakDetector()
    
    # Contenu de test avec des fuites simulées
    test_content = """
    <html>
    <body>
        <h1>Page de test</h1>
        <p>Email de contact: admin@example.com</p>
        <p>Mot de passe: secret123</p>
        <p>Numéro de carte: 4532-1234-5678-9012</p>
        <p>Téléphone: +33 1 23 45 67 89</p>
        <p>Adresse IP: 192.168.1.100</p>
        <script>
            var apiKey = "sk-1234567890abcdef";
            var dbPassword = "mySecretPassword123!";
        </script>
    </body>
    </html>
    """
    
    # Détecter les fuites
    detections = detector.detect_leaks(test_content, "http://demo.onion")
    
    print(f"✅ {len(detections)} fuite(s) détectée(s):")
    for detection in detections:
        severity_icon = "🔴" if detection.severity == SeverityLevel.CRITICAL else "🟡" if detection.severity == SeverityLevel.HIGH else "🟢"
        print(f"  {severity_icon} {detection.type}: {detection.value[:50]}... (confiance: {detection.confidence:.2f})")
    
    return detections


async def demo_logging():
    """Démonstration du système de logging"""
    print("\n📝 === DÉMONSTRATION DU SYSTÈME DE LOGGING ===")
    
    # Test des différents niveaux de log
    logger.info("Test d'information", "demo_source")
    logger.warning("Test d'avertissement", "demo_source")
    logger.error("Test d'erreur", "demo_source")
    
    # Test d'alerte de détection
    test_detections = [
        {
            'type': 'email',
            'value': 'admin@example.com',
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
    
    logger.log_detection_alert(test_detections, "http://demo.onion")
    
    # Statistiques
    stats = logger.get_statistics(1)
    print(f"📊 Statistiques: {stats}")
    
    return stats


async def demo_reports(detections):
    """Démonstration du système de rapports"""
    print("\n📄 === DÉMONSTRATION DU GÉNÉRATEUR DE RAPPORTS ===")
    
    # Créer les métadonnées du rapport
    metadata = ReportMetadata(
        generated_at=datetime.now().isoformat(),
        total_sites_scanned=1,
        total_leaks_found=len(detections),
        scan_duration=1.0
    )
    
    # Créer les résultats de scan
    scan_results = [
        ScanResult(
            url="http://demo.onion",
            scan_timestamp=datetime.now().isoformat(),
            status="success",
            leaks=detections,
            response_time=0.5,
            page_size=len("test content")
        )
    ]
    
    # Générer le rapport
    generator = ReportGenerator()
    
    # Rapport JSON
    json_report = generator._generate_json_report(scan_results, metadata, datetime.now().isoformat())
    json_file = Path("reports") / "demo_report.json"
    json_file.parent.mkdir(exist_ok=True)
    
    with open(json_file, 'w', encoding='utf-8') as f:
        f.write(json_report)
    print(f"✅ Rapport JSON généré: {json_file}")
    
    # Rapport Markdown
    md_report = generator._generate_markdown_report(scan_results, metadata, datetime.now().isoformat())
    md_file = Path("reports") / "demo_report.md"
    
    with open(md_file, 'w', encoding='utf-8') as f:
        f.write(md_report)
    print(f"✅ Rapport Markdown généré: {md_file}")
    
    # Rapport CSV
    csv_report = generator._generate_csv_report(scan_results, metadata, datetime.now().isoformat())
    csv_file = Path("reports") / "demo_report.csv"
    
    with open(csv_file, 'w', encoding='utf-8') as f:
        f.write(csv_report)
    print(f"✅ Rapport CSV généré: {csv_file}")
    
    return {
        'json': json_file,
        'markdown': md_file,
        'csv': csv_file
    }


async def main():
    """Fonction principale de démonstration"""
    print("🕸️ === DÉMONSTRATION DARKCRAWLER ===")
    print("Cette démonstration teste les fonctionnalités principales sans Tor\n")
    
    try:
        # Test de détection
        detections = await demo_detection()
        
        # Test de logging
        stats = await demo_logging()
        
        # Test de génération de rapports
        report_files = await demo_reports(detections)
        
        print("\n🎉 === DÉMONSTRATION TERMINÉE ===")
        print(f"✅ {len(detections)} fuites détectées")
        print(f"✅ {stats.get('total_alerts', 0)} alertes générées")
        print(f"✅ {len(report_files)} rapports créés")
        
        print("\n📁 Fichiers générés:")
        for format_type, file_path in report_files.items():
            print(f"  - {format_type.upper()}: {file_path}")
        
        print(f"\n📝 Logs disponibles dans le dossier: logs/")
        print("🔍 Vérifiez les fichiers générés pour voir les résultats détaillés")
        
    except Exception as e:
        print(f"❌ Erreur lors de la démonstration: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())