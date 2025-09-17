#!/usr/bin/env python3
"""
Interface Web pour DarkCrawler
Permet de visualiser les résultats de scan et les rapports générés
"""

import os
import json
import asyncio
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

from flask import Flask, render_template, jsonify, request, send_file
from flask_socketio import SocketIO, emit

# Import des modules DarkCrawler
from alerts.logger import darkcrawler_logger
from crawler.detector import DataLeakDetector
from reports.generator import ReportGenerator, ReportMetadata, ScanResult

app = Flask(__name__)
app.config['SECRET_KEY'] = 'darkcrawler_secret_key_2024'
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuration
REPORTS_DIR = Path("reports")
LOGS_DIR = Path("logs")

class WebInterface:
    def __init__(self):
        self.detector = DataLeakDetector()
        self.report_generator = ReportGenerator()
        self.active_scans = {}
        
    def get_recent_reports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Récupère les rapports récents"""
        reports = []
        
        # Parcourir les fichiers JSON dans le dossier reports
        if REPORTS_DIR.exists():
            json_files = list(REPORTS_DIR.glob("*.json"))
            json_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
            
            for json_file in json_files[:limit]:
                try:
                    with open(json_file, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        reports.append({
                            'filename': json_file.name,
                            'created': datetime.fromtimestamp(json_file.stat().st_mtime).isoformat(),
                            'data': data
                        })
                except Exception as e:
                    darkcrawler_logger.error(f"Erreur lecture rapport {json_file}: {e}")
                    
        return reports
    
    def get_scan_statistics(self) -> Dict[str, Any]:
        """Calcule les statistiques globales"""
        reports = self.get_recent_reports(100)  # Analyser les 100 derniers rapports
        
        total_scans = len(reports)
        total_leaks = 0
        leak_types = {}
        severity_counts = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
        
        for report in reports:
            if 'scan_results' in report['data']:
                for result in report['data']['scan_results']:
                    if 'leaks' in result:
                        total_leaks += len(result['leaks'])
                        for leak in result['leaks']:
                            # Compter par type
                            leak_type = leak.get('type', 'unknown')
                            leak_types[leak_type] = leak_types.get(leak_type, 0) + 1
                            
                            # Compter par sévérité
                            severity = leak.get('severity', 'low').lower()
                            if severity in severity_counts:
                                severity_counts[severity] += 1
        
        return {
            'total_scans': total_scans,
            'total_leaks': total_leaks,
            'leak_types': leak_types,
            'severity_distribution': severity_counts,
            'last_scan': reports[0]['created'] if reports else None
        }

# Instance globale
web_interface = WebInterface()

@app.route('/')
def index():
    """Page d'accueil"""
    return render_template('index.html')

@app.route('/api/reports')
def api_reports():
    """API pour récupérer les rapports"""
    limit = request.args.get('limit', 10, type=int)
    reports = web_interface.get_recent_reports(limit)
    return jsonify(reports)

@app.route('/api/statistics')
def api_statistics():
    """API pour les statistiques"""
    stats = web_interface.get_scan_statistics()
    return jsonify(stats)

@app.route('/api/report/<filename>')
def api_report_detail(filename):
    """API pour récupérer un rapport spécifique"""
    try:
        report_path = REPORTS_DIR / filename
        if report_path.exists() and report_path.suffix == '.json':
            with open(report_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            return jsonify(data)
        else:
            return jsonify({'error': 'Rapport non trouvé'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download_report(filename):
    """Télécharger un rapport"""
    try:
        report_path = REPORTS_DIR / filename
        if report_path.exists():
            return send_file(report_path, as_attachment=True)
        else:
            return "Fichier non trouvé", 404
    except Exception as e:
        return f"Erreur: {str(e)}", 500

@socketio.on('connect')
def handle_connect():
    """Gestion des connexions WebSocket"""
    darkcrawler_logger.info("Client connecté à l'interface web")
    emit('status', {'message': 'Connecté à DarkCrawler'})

@socketio.on('disconnect')
def handle_disconnect():
    """Gestion des déconnexions WebSocket"""
    darkcrawler_logger.info("Client déconnecté de l'interface web")

def create_templates():
    """Crée les templates HTML nécessaires"""
    templates_dir = Path("templates")
    templates_dir.mkdir(exist_ok=True)
    
    # Template principal
    index_html = """<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🕸️ DarkCrawler - Interface Web</title>
    <script src="https://cdn.socket.io/4.0.0/socket.io.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a1a; color: #fff; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { text-align: center; margin-bottom: 30px; }
        .header h1 { color: #00ff88; font-size: 2.5em; margin-bottom: 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #2a2a2a; padding: 20px; border-radius: 10px; border-left: 4px solid #00ff88; }
        .stat-card h3 { color: #00ff88; margin-bottom: 10px; }
        .stat-card .value { font-size: 2em; font-weight: bold; }
        .reports-section { background: #2a2a2a; padding: 20px; border-radius: 10px; margin-bottom: 20px; }
        .reports-section h2 { color: #00ff88; margin-bottom: 20px; }
        .report-item { background: #3a3a3a; padding: 15px; margin-bottom: 10px; border-radius: 5px; border-left: 3px solid #00ff88; }
        .report-item h4 { color: #fff; margin-bottom: 5px; }
        .report-item .meta { color: #aaa; font-size: 0.9em; }
        .charts-section { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 20px; }
        .chart-container { background: #2a2a2a; padding: 20px; border-radius: 10px; }
        .status { position: fixed; top: 20px; right: 20px; background: #00ff88; color: #000; padding: 10px 20px; border-radius: 5px; }
        .severity-high { border-left-color: #ff4444; }
        .severity-critical { border-left-color: #ff0000; }
        .severity-medium { border-left-color: #ffaa00; }
        .severity-low { border-left-color: #00ff88; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🕸️ DarkCrawler</h1>
            <p>Interface de monitoring et visualisation des résultats</p>
        </div>
        
        <div id="status" class="status" style="display: none;"></div>
        
        <div class="stats-grid" id="stats-grid">
            <!-- Les statistiques seront chargées ici -->
        </div>
        
        <div class="charts-section">
            <div class="chart-container">
                <h3 style="color: #00ff88; margin-bottom: 15px;">Types de fuites</h3>
                <canvas id="leakTypesChart"></canvas>
            </div>
            <div class="chart-container">
                <h3 style="color: #00ff88; margin-bottom: 15px;">Distribution des sévérités</h3>
                <canvas id="severityChart"></canvas>
            </div>
        </div>
        
        <div class="reports-section">
            <h2>📄 Rapports récents</h2>
            <div id="reports-list">
                <!-- Les rapports seront chargés ici -->
            </div>
        </div>
    </div>

    <script>
        // Connexion WebSocket
        const socket = io();
        
        socket.on('connect', function() {
            document.getElementById('status').style.display = 'block';
            document.getElementById('status').textContent = '🟢 Connecté';
        });
        
        socket.on('disconnect', function() {
            document.getElementById('status').style.display = 'block';
            document.getElementById('status').textContent = '🔴 Déconnecté';
        });
        
        // Chargement des données
        async function loadStatistics() {
            try {
                const response = await fetch('/api/statistics');
                const stats = await response.json();
                
                const statsGrid = document.getElementById('stats-grid');
                statsGrid.innerHTML = `
                    <div class="stat-card">
                        <h3>📊 Total Scans</h3>
                        <div class="value">${stats.total_scans}</div>
                    </div>
                    <div class="stat-card">
                        <h3>🚨 Total Fuites</h3>
                        <div class="value">${stats.total_leaks}</div>
                    </div>
                    <div class="stat-card">
                        <h3>📅 Dernier Scan</h3>
                        <div class="value" style="font-size: 1.2em;">${stats.last_scan ? new Date(stats.last_scan).toLocaleDateString() : 'N/A'}</div>
                    </div>
                    <div class="stat-card">
                        <h3>🎯 Types Détectés</h3>
                        <div class="value">${Object.keys(stats.leak_types).length}</div>
                    </div>
                `;
                
                // Graphiques
                createLeakTypesChart(stats.leak_types);
                createSeverityChart(stats.severity_distribution);
                
            } catch (error) {
                console.error('Erreur chargement statistiques:', error);
            }
        }
        
        async function loadReports() {
            try {
                const response = await fetch('/api/reports?limit=10');
                const reports = await response.json();
                
                const reportsList = document.getElementById('reports-list');
                reportsList.innerHTML = reports.map(report => {
                    const totalLeaks = report.data.scan_results ? 
                        report.data.scan_results.reduce((sum, result) => sum + (result.leaks ? result.leaks.length : 0), 0) : 0;
                    
                    return `
                        <div class="report-item">
                            <h4>📄 ${report.filename}</h4>
                            <div class="meta">
                                📅 ${new Date(report.created).toLocaleString()} | 
                                🚨 ${totalLeaks} fuite(s) | 
                                <a href="/download/${report.filename}" style="color: #00ff88;">Télécharger</a>
                            </div>
                        </div>
                    `;
                }).join('');
                
            } catch (error) {
                console.error('Erreur chargement rapports:', error);
            }
        }
        
        function createLeakTypesChart(leakTypes) {
            const ctx = document.getElementById('leakTypesChart').getContext('2d');
            new Chart(ctx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(leakTypes),
                    datasets: [{
                        data: Object.values(leakTypes),
                        backgroundColor: ['#ff4444', '#ffaa00', '#00ff88', '#0088ff', '#aa00ff']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { labels: { color: '#fff' } }
                    }
                }
            });
        }
        
        function createSeverityChart(severityData) {
            const ctx = document.getElementById('severityChart').getContext('2d');
            new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: ['Faible', 'Moyen', 'Élevé', 'Critique'],
                    datasets: [{
                        data: [severityData.low, severityData.medium, severityData.high, severityData.critical],
                        backgroundColor: ['#00ff88', '#ffaa00', '#ff4444', '#ff0000']
                    }]
                },
                options: {
                    responsive: true,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: { ticks: { color: '#fff' } },
                        x: { ticks: { color: '#fff' } }
                    }
                }
            });
        }
        
        // Chargement initial
        loadStatistics();
        loadReports();
        
        // Actualisation automatique toutes les 30 secondes
        setInterval(() => {
            loadStatistics();
            loadReports();
        }, 30000);
    </script>
</body>
</html>"""
    
    with open(templates_dir / "index.html", "w", encoding="utf-8") as f:
        f.write(index_html)

def main():
    """Fonction principale pour lancer l'interface web"""
    print("🕸️ Démarrage de l'interface web DarkCrawler...")
    
    # Créer les dossiers nécessaires
    REPORTS_DIR.mkdir(exist_ok=True)
    LOGS_DIR.mkdir(exist_ok=True)
    
    # Créer les templates
    create_templates()
    
    # Démarrer le serveur
    darkcrawler_logger.info("Interface web démarrée sur http://localhost:5001")
    socketio.run(app, host='0.0.0.0', port=5001, debug=False)

if __name__ == "__main__":
    main()