"""
Module de détection de fuites pour DarkCrawler
Détecte les données sensibles dans le contenu web avec des regex avancées
"""

import re
import json
import logging
from typing import List, Dict, Set, Optional, Tuple, Any
from datetime import datetime
from dataclasses import dataclass, asdict
from enum import Enum


class SeverityLevel(Enum):
    """Niveaux de sévérité pour les fuites détectées"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LeakDetection:
    """Représente une fuite détectée"""
    type: str
    value: str
    context: str
    severity: SeverityLevel
    confidence: float
    position: int
    timestamp: datetime
    source_url: str = ""
    additional_info: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_info is None:
            self.additional_info = {}
    
    def to_dict(self) -> Dict:
        """Convertit la détection en dictionnaire"""
        data = asdict(self)
        data['severity'] = self.severity.value
        data['timestamp'] = self.timestamp.isoformat()
        return data


class DataLeakDetector:
    """Détecteur de fuites de données sensibles"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialise le détecteur
        
        Args:
            config_path: Chemin vers le fichier de configuration
        """
        self.logger = logging.getLogger(__name__)
        self.patterns = {}
        self.keywords = []
        self.custom_patterns = {}
        
        # Charger la configuration
        if config_path:
            self.load_config(config_path)
        else:
            self._load_default_patterns()
    
    def load_config(self, config_path: str):
        """
        Charge la configuration depuis un fichier JSON
        
        Args:
            config_path: Chemin vers le fichier de configuration
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            
            self.patterns = config.get('patterns', {})
            self.keywords = config.get('keywords', [])
            
            # Compiler les regex
            for pattern_name, pattern_info in self.patterns.items():
                try:
                    pattern_info['compiled'] = re.compile(
                        pattern_info['regex'], 
                        re.IGNORECASE | re.MULTILINE
                    )
                except re.error as e:
                    self.logger.error(f"Erreur compilation regex {pattern_name}: {e}")
            
            self.logger.info(f"Configuration chargée: {len(self.patterns)} patterns")
            
        except Exception as e:
            self.logger.error(f"Erreur chargement config: {e}")
            self._load_default_patterns()
    
    def _load_default_patterns(self):
        """Charge les patterns par défaut"""
        self.patterns = {
            'email': {
                'regex': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
                'description': 'Adresses email',
                'severity': 'medium',
                'compiled': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE)
            },
            'username': {
                'regex': r'(?i)(?:username|user|login|account)[:=\s]+([^\s\n\r<>]{3,50})',
                'description': 'Identifiants utilisateur',
                'severity': 'high',
                'compiled': re.compile(r'(?i)(?:username|user|login|account)[:=\s]+([^\s\n\r<>]{3,50})', re.IGNORECASE)
            },
            'password': {
                'regex': r'(?i)(?:password|pass|pwd)[:=\s]+([^\s\n\r<>]{3,50})',
                'description': 'Mots de passe',
                'severity': 'critical',
                'compiled': re.compile(r'(?i)(?:password|pass|pwd)[:=\s]+([^\s\n\r<>]{3,50})', re.IGNORECASE)
            },
            'credit_card': {
                'regex': r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
                'description': 'Numéros de carte de crédit',
                'severity': 'critical',
                'compiled': re.compile(r'\b(?:\d{4}[\s-]?){3}\d{4}\b')
            },
            'ssn': {
                'regex': r'\b\d{3}-\d{2}-\d{4}\b',
                'description': 'Numéros de sécurité sociale',
                'severity': 'critical',
                'compiled': re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
            },
            'phone': {
                'regex': r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b',
                'description': 'Numéros de téléphone',
                'severity': 'low',
                'compiled': re.compile(r'\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b')
            },
            'api_key': {
                'regex': r'(?i)(?:api[_-]?key|apikey)[:=\s]+([A-Za-z0-9_-]{16,})',
                'description': 'Clés API',
                'severity': 'critical',
                'compiled': re.compile(r'(?i)(?:api[_-]?key|apikey)[:=\s]+([A-Za-z0-9_-]{16,})', re.IGNORECASE)
            },
            'token': {
                'regex': r'(?i)(?:token|auth[_-]?token|bearer)[:=\s]+([A-Za-z0-9_.-]{20,})',
                'description': 'Tokens d\'authentification',
                'severity': 'critical',
                'compiled': re.compile(r'(?i)(?:token|auth[_-]?token|bearer)[:=\s]+([A-Za-z0-9_.-]{20,})', re.IGNORECASE)
            },
            'private_key': {
                'regex': r'-----BEGIN (?:RSA )?PRIVATE KEY-----',
                'description': 'Clés privées',
                'severity': 'critical',
                'compiled': re.compile(r'-----BEGIN (?:RSA )?PRIVATE KEY-----')
            },
            'bitcoin_address': {
                'regex': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
                'description': 'Adresses Bitcoin',
                'severity': 'medium',
                'compiled': re.compile(r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b')
            },
            'ip_address': {
                'regex': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
                'description': 'Adresses IP',
                'severity': 'low',
                'compiled': re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
            },
            'database_connection': {
                'regex': r'(?i)(?:mysql|postgresql|mongodb|redis)://[^\s<>]+',
                'description': 'Chaînes de connexion base de données',
                'severity': 'critical',
                'compiled': re.compile(r'(?i)(?:mysql|postgresql|mongodb|redis)://[^\s<>]+', re.IGNORECASE)
            }
        }
        
        self.keywords = [
            'leak', 'breach', 'dump', 'database', 'credentials', 'login',
            'hack', 'stolen', 'compromised', 'exposed', 'vulnerability',
            'exploit', 'backdoor', 'malware', 'ransomware', 'phishing'
        ]
    
    def detect_leaks(self, content: str, source_url: str = "") -> List[LeakDetection]:
        """
        Détecte les fuites dans le contenu
        
        Args:
            content: Contenu à analyser
            source_url: URL source du contenu
            
        Returns:
            List[LeakDetection]: Liste des fuites détectées
        """
        detections = []
        
        if not content:
            return detections
        
        # Détecter avec les patterns configurés
        for pattern_name, pattern_info in self.patterns.items():
            pattern_detections = self._detect_pattern(
                content, pattern_name, pattern_info, source_url
            )
            detections.extend(pattern_detections)
        
        # Détecter les mots-clés suspects
        keyword_detections = self._detect_keywords(content, source_url)
        detections.extend(keyword_detections)
        
        # Détecter les patterns personnalisés
        custom_detections = self._detect_custom_patterns(content, source_url)
        detections.extend(custom_detections)
        
        # Trier par sévérité et position
        detections.sort(key=lambda x: (x.severity.value, x.position))
        
        self.logger.info(f"Détections trouvées: {len(detections)}")
        return detections
    
    def _detect_pattern(self, content: str, pattern_name: str, 
                       pattern_info: Dict, source_url: str) -> List[LeakDetection]:
        """
        Détecte un pattern spécifique dans le contenu
        
        Args:
            content: Contenu à analyser
            pattern_name: Nom du pattern
            pattern_info: Informations du pattern
            source_url: URL source
            
        Returns:
            List[LeakDetection]: Détections pour ce pattern
        """
        detections = []
        
        try:
            compiled_regex = pattern_info.get('compiled')
            if not compiled_regex:
                return detections
            
            matches = compiled_regex.finditer(content)
            
            for match in matches:
                # Extraire la valeur (groupe 1 si existe, sinon match complet)
                value = match.group(1) if match.groups() else match.group(0)
                
                # Calculer la confiance basée sur la longueur et le contexte
                confidence = self._calculate_confidence(value, pattern_name, content, match.start())
                
                # Filtrer les faux positifs
                if confidence < 0.3:
                    continue
                
                detection = LeakDetection(
                    type=pattern_name,
                    value=value,
                    context=self._extract_context(content, match.start(), match.end()),
                    severity=SeverityLevel(pattern_info.get('severity', 'medium')),
                    confidence=confidence,
                    position=match.start(),
                    timestamp=datetime.now(),
                    source_url=source_url,
                    additional_info={
                        'description': pattern_info.get('description', ''),
                        'full_match': match.group(0)
                    }
                )
                
                detections.append(detection)
                
        except Exception as e:
            self.logger.error(f"Erreur détection pattern {pattern_name}: {e}")
        
        return detections
    
    def _detect_keywords(self, content: str, source_url: str) -> List[LeakDetection]:
        """
        Détecte les mots-clés suspects dans le contenu
        
        Args:
            content: Contenu à analyser
            source_url: URL source
            
        Returns:
            List[LeakDetection]: Détections de mots-clés
        """
        detections = []
        content_lower = content.lower()
        
        for keyword in self.keywords:
            pattern = re.compile(rf'\b{re.escape(keyword)}\b', re.IGNORECASE)
            matches = pattern.finditer(content)
            
            for match in matches:
                # Analyser le contexte pour déterminer la pertinence
                context = self._extract_context(content, match.start(), match.end(), 100)
                confidence = self._calculate_keyword_confidence(keyword, context)
                
                if confidence > 0.5:
                    detection = LeakDetection(
                        type='suspicious_keyword',
                        value=keyword,
                        context=context,
                        severity=SeverityLevel.LOW,
                        confidence=confidence,
                        position=match.start(),
                        timestamp=datetime.now(),
                        source_url=source_url,
                        additional_info={
                            'description': f'Mot-clé suspect: {keyword}',
                            'keyword_category': self._categorize_keyword(keyword)
                        }
                    )
                    detections.append(detection)
        
        return detections
    
    def _detect_custom_patterns(self, content: str, source_url: str) -> List[LeakDetection]:
        """
        Détecte avec des patterns personnalisés
        
        Args:
            content: Contenu à analyser
            source_url: URL source
            
        Returns:
            List[LeakDetection]: Détections personnalisées
        """
        detections = []
        
        # Patterns pour détecter des structures de données
        data_patterns = {
            'json_credentials': {
                'regex': r'\{[^}]*(?:"(?:username|password|email|token|key)"[^}]*){2,}[^}]*\}',
                'severity': 'high',
                'description': 'Structure JSON avec credentials'
            },
            'url_with_credentials': {
                'regex': r'https?://[^:]+:[^@]+@[^\s<>]+',
                'severity': 'critical',
                'description': 'URL avec credentials intégrés'
            },
            'base64_potential': {
                'regex': r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
                'severity': 'low',
                'description': 'Données potentiellement encodées en Base64'
            }
        }
        
        for pattern_name, pattern_info in data_patterns.items():
            try:
                regex = re.compile(pattern_info['regex'], re.IGNORECASE | re.MULTILINE)
                matches = regex.finditer(content)
                
                for match in matches:
                    value = match.group(0)
                    
                    # Filtrer les matches trop courts ou trop longs
                    if len(value) < 10 or len(value) > 500:
                        continue
                    
                    confidence = self._calculate_confidence(value, pattern_name, content, match.start())
                    
                    if confidence > 0.4:
                        detection = LeakDetection(
                            type=pattern_name,
                            value=value,
                            context=self._extract_context(content, match.start(), match.end()),
                            severity=SeverityLevel(pattern_info['severity']),
                            confidence=confidence,
                            position=match.start(),
                            timestamp=datetime.now(),
                            source_url=source_url,
                            additional_info={
                                'description': pattern_info['description']
                            }
                        )
                        detections.append(detection)
                        
            except Exception as e:
                self.logger.error(f"Erreur pattern personnalisé {pattern_name}: {e}")
        
        return detections
    
    def _calculate_confidence(self, value: str, pattern_type: str, 
                            content: str, position: int) -> float:
        """
        Calcule la confiance d'une détection
        
        Args:
            value: Valeur détectée
            pattern_type: Type de pattern
            content: Contenu complet
            position: Position dans le contenu
            
        Returns:
            float: Score de confiance (0-1)
        """
        confidence = 0.5  # Base
        
        # Facteurs basés sur la longueur
        if pattern_type in ['password', 'api_key', 'token']:
            if len(value) >= 8:
                confidence += 0.2
            if len(value) >= 16:
                confidence += 0.2
        
        # Facteurs basés sur le contexte
        context = self._extract_context(content, position, position + len(value), 50)
        context_lower = context.lower()
        
        # Mots-clés qui augmentent la confiance
        positive_keywords = ['password', 'secret', 'key', 'token', 'credential', 'login']
        for keyword in positive_keywords:
            if keyword in context_lower:
                confidence += 0.1
        
        # Mots-clés qui diminuent la confiance
        negative_keywords = ['example', 'test', 'demo', 'placeholder', 'sample']
        for keyword in negative_keywords:
            if keyword in context_lower:
                confidence -= 0.3
        
        # Validation spécifique par type
        if pattern_type == 'email':
            confidence = self._validate_email_confidence(value, confidence)
        elif pattern_type == 'credit_card':
            confidence = self._validate_credit_card_confidence(value, confidence)
        elif pattern_type == 'ip_address':
            confidence = self._validate_ip_confidence(value, confidence)
        
        return max(0.0, min(1.0, confidence))
    
    def _calculate_keyword_confidence(self, keyword: str, context: str) -> float:
        """
        Calcule la confiance pour un mot-clé
        
        Args:
            keyword: Mot-clé détecté
            context: Contexte autour du mot-clé
            
        Returns:
            float: Score de confiance
        """
        confidence = 0.3  # Base faible pour les mots-clés
        
        context_lower = context.lower()
        
        # Augmenter si dans un contexte technique
        technical_terms = ['database', 'server', 'admin', 'root', 'config', 'sql']
        for term in technical_terms:
            if term in context_lower:
                confidence += 0.2
        
        # Augmenter si associé à des données sensibles
        sensitive_terms = ['password', 'credential', 'access', 'login', 'user']
        for term in sensitive_terms:
            if term in context_lower:
                confidence += 0.3
        
        return min(1.0, confidence)
    
    def _validate_email_confidence(self, email: str, base_confidence: float) -> float:
        """Valide la confiance d'une adresse email"""
        # Domaines suspects
        suspicious_domains = ['tempmail', '10minutemail', 'guerrillamail']
        for domain in suspicious_domains:
            if domain in email.lower():
                return base_confidence + 0.2
        
        # Domaines communs (moins suspects)
        common_domains = ['gmail', 'yahoo', 'hotmail', 'outlook']
        for domain in common_domains:
            if domain in email.lower():
                return base_confidence - 0.1
        
        return base_confidence
    
    def _validate_credit_card_confidence(self, card: str, base_confidence: float) -> float:
        """Valide la confiance d'un numéro de carte de crédit"""
        # Algorithme de Luhn simplifié
        digits = re.sub(r'\D', '', card)
        if len(digits) != 16:
            return base_confidence - 0.3
        
        # Vérifier les préfixes connus
        known_prefixes = ['4', '5', '37', '6']  # Visa, MC, Amex, Discover
        if any(digits.startswith(prefix) for prefix in known_prefixes):
            return base_confidence + 0.2
        
        return base_confidence
    
    def _validate_ip_confidence(self, ip: str, base_confidence: float) -> float:
        """Valide la confiance d'une adresse IP"""
        parts = ip.split('.')
        
        # Vérifier la validité des octets
        try:
            octets = [int(part) for part in parts]
            if all(0 <= octet <= 255 for octet in octets):
                # IP privées sont moins critiques
                if (octets[0] == 10 or 
                    (octets[0] == 172 and 16 <= octets[1] <= 31) or
                    (octets[0] == 192 and octets[1] == 168)):
                    return base_confidence - 0.2
                return base_confidence + 0.1
        except ValueError:
            return base_confidence - 0.5
        
        return base_confidence
    
    def _extract_context(self, content: str, start: int, end: int, 
                        context_length: int = 50) -> str:
        """
        Extrait le contexte autour d'une détection
        
        Args:
            content: Contenu complet
            start: Position de début
            end: Position de fin
            context_length: Longueur du contexte de chaque côté
            
        Returns:
            str: Contexte extrait
        """
        context_start = max(0, start - context_length)
        context_end = min(len(content), end + context_length)
        
        context = content[context_start:context_end]
        
        # Nettoyer le contexte
        context = re.sub(r'\s+', ' ', context)
        context = context.strip()
        
        # Marquer la partie détectée
        relative_start = start - context_start
        relative_end = end - context_start
        
        if relative_start >= 0 and relative_end <= len(context):
            detected_part = context[relative_start:relative_end]
            context = (context[:relative_start] + 
                      f"**{detected_part}**" + 
                      context[relative_end:])
        
        return context
    
    def _categorize_keyword(self, keyword: str) -> str:
        """Catégorise un mot-clé"""
        categories = {
            'security': ['hack', 'exploit', 'vulnerability', 'breach', 'compromised'],
            'data': ['leak', 'dump', 'database', 'credentials', 'exposed'],
            'malware': ['malware', 'ransomware', 'backdoor', 'phishing'],
            'access': ['login', 'password', 'admin', 'root']
        }
        
        for category, keywords in categories.items():
            if keyword.lower() in keywords:
                return category
        
        return 'general'
    
    def add_custom_pattern(self, name: str, regex: str, severity: str, 
                          description: str = ""):
        """
        Ajoute un pattern personnalisé
        
        Args:
            name: Nom du pattern
            regex: Expression régulière
            severity: Niveau de sévérité
            description: Description du pattern
        """
        try:
            compiled_regex = re.compile(regex, re.IGNORECASE | re.MULTILINE)
            
            self.custom_patterns[name] = {
                'regex': regex,
                'compiled': compiled_regex,
                'severity': severity,
                'description': description
            }
            
            self.logger.info(f"Pattern personnalisé ajouté: {name}")
            
        except re.error as e:
            self.logger.error(f"Erreur regex pattern {name}: {e}")
    
    def get_statistics(self, detections: List[LeakDetection]) -> Dict:
        """
        Génère des statistiques sur les détections
        
        Args:
            detections: Liste des détections
            
        Returns:
            Dict: Statistiques
        """
        if not detections:
            return {}
        
        stats = {
            'total_detections': len(detections),
            'by_type': {},
            'by_severity': {},
            'average_confidence': 0,
            'high_confidence_count': 0,
            'unique_sources': set()
        }
        
        total_confidence = 0
        
        for detection in detections:
            # Par type
            stats['by_type'][detection.type] = stats['by_type'].get(detection.type, 0) + 1
            
            # Par sévérité
            severity = detection.severity.value
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1
            
            # Confiance
            total_confidence += detection.confidence
            if detection.confidence >= 0.8:
                stats['high_confidence_count'] += 1
            
            # Sources
            if detection.source_url:
                stats['unique_sources'].add(detection.source_url)
        
        stats['average_confidence'] = total_confidence / len(detections)
        stats['unique_sources'] = len(stats['unique_sources'])
        
        return stats


if __name__ == "__main__":
    # Test du module
    logging.basicConfig(level=logging.INFO)
    
    print("🔍 Test du module DataLeakDetector")
    
    # Contenu de test
    test_content = """
    Welcome to our service!
    
    Admin credentials:
    Username: admin@company.com
    Password: SuperSecret123!
    
    API Key: sk_live_1234567890abcdef
    Database: mysql://user:pass@localhost/db
    
    Credit Card: 4532-1234-5678-9012
    Phone: +1-555-123-4567
    
    This is a data breach dump containing sensitive information.
    """
    
    detector = DataLeakDetector()
    detections = detector.detect_leaks(test_content, "http://test.onion/leak")
    
    print(f"✅ Détections trouvées: {len(detections)}")
    
    for detection in detections:
        print(f"   - {detection.type}: {detection.value} (sévérité: {detection.severity.value})")
    
    # Statistiques
    stats = detector.get_statistics(detections)
    print(f"✅ Statistiques: {stats}")