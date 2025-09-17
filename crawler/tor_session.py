"""
Module de gestion des sessions Tor pour DarkCrawler
Gère la connexion au réseau Tor via proxy SOCKS5
"""

import requests
import time
import random
import logging
from typing import Optional, Dict, Any
import socket
import subprocess
import sys

class TorSession:
    """Gestionnaire de session Tor pour accéder au dark web"""
    
    def __init__(self, 
                 proxy_host: str = "127.0.0.1", 
                 proxy_port: int = 9050,
                 control_port: int = 9051):
        """
        Initialise une session Tor
        
        Args:
            proxy_host: Adresse du proxy Tor (défaut: 127.0.0.1)
            proxy_port: Port du proxy SOCKS5 (défaut: 9050)
            control_port: Port de contrôle Tor (défaut: 9051)
        """
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.control_port = control_port
        self.session = None
        self.logger = logging.getLogger(__name__)
        
        # Configuration des proxies
        self.proxies = {
            'http': f'socks5h://{proxy_host}:{proxy_port}',
            'https': f'socks5h://{proxy_host}:{proxy_port}'
        }
        
        # Headers par défaut pour l'anonymat
        self.default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }
    
    def check_tor_connection(self) -> bool:
        """
        Vérifie si Tor est accessible
        
        Returns:
            bool: True si Tor est accessible, False sinon
        """
        try:
            # Test de connexion au port SOCKS5
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.proxy_host, self.proxy_port))
            sock.close()
            
            if result != 0:
                self.logger.error(f"Impossible de se connecter au proxy Tor sur {self.proxy_host}:{self.proxy_port}")
                return False
            
            self.logger.info("Connexion au proxy Tor réussie")
            return True
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la vérification de Tor: {e}")
            return False
    
    def get_tor_ip(self) -> Optional[str]:
        """
        Récupère l'adresse IP actuelle via Tor
        
        Returns:
            str: Adresse IP ou None en cas d'erreur
        """
        try:
            response = self.session.get(
                'http://httpbin.org/ip',
                timeout=30
            )
            if response.status_code == 200:
                ip = response.json().get('origin')
                self.logger.info(f"IP Tor actuelle: {ip}")
                return ip
        except Exception as e:
            self.logger.error(f"Impossible de récupérer l'IP Tor: {e}")
        return None
    
    def create_session(self, user_agent: Optional[str] = None) -> requests.Session:
        """
        Crée une nouvelle session avec configuration Tor
        
        Args:
            user_agent: User-Agent personnalisé (optionnel)
            
        Returns:
            requests.Session: Session configurée pour Tor
        """
        session = requests.Session()
        session.proxies.update(self.proxies)
        
        # Configuration des headers
        headers = self.default_headers.copy()
        if user_agent:
            headers['User-Agent'] = user_agent
        
        session.headers.update(headers)
        
        # Configuration des timeouts et retry
        session.timeout = 30
        
        self.session = session
        self.logger.info("Session Tor créée avec succès")
        return session
    
    def get_new_identity(self) -> bool:
        """
        Demande une nouvelle identité Tor (nouvelle IP)
        
        Returns:
            bool: True si succès, False sinon
        """
        try:
            # Tentative de connexion au port de contrôle Tor
            import telnetlib
            
            tn = telnetlib.Telnet(self.proxy_host, self.control_port, timeout=10)
            tn.write(b"AUTHENTICATE\r\n")
            tn.write(b"SIGNAL NEWNYM\r\n")
            tn.write(b"QUIT\r\n")
            tn.close()
            
            # Attendre que la nouvelle identité soit active
            time.sleep(10)
            
            self.logger.info("Nouvelle identité Tor demandée")
            return True
            
        except Exception as e:
            self.logger.warning(f"Impossible de changer d'identité Tor: {e}")
            return False
    
    def test_onion_connectivity(self) -> bool:
        """
        Test la connectivité aux services .onion
        
        Returns:
            bool: True si les services .onion sont accessibles
        """
        try:
            # Test avec DuckDuckGo onion (service stable)
            test_url = "https://3g2upl4pq6kufc4m.onion"
            
            if not self.session:
                self.create_session()
            
            response = self.session.get(test_url, timeout=30)
            
            if response.status_code == 200:
                self.logger.info("Connectivité .onion confirmée")
                return True
            else:
                self.logger.warning(f"Test .onion échoué: {response.status_code}")
                return False
                
        except Exception as e:
            self.logger.error(f"Erreur test .onion: {e}")
            return False
    
    def safe_request(self, 
                    url: str, 
                    method: str = 'GET', 
                    delay: float = 2.0,
                    **kwargs) -> Optional[requests.Response]:
        """
        Effectue une requête sécurisée avec gestion d'erreurs
        
        Args:
            url: URL à requêter
            method: Méthode HTTP (GET, POST, etc.)
            delay: Délai avant la requête (secondes)
            **kwargs: Arguments supplémentaires pour requests
            
        Returns:
            requests.Response: Réponse ou None en cas d'erreur
        """
        try:
            # Délai aléatoire pour éviter la détection
            time.sleep(delay + random.uniform(0, 1))
            
            if not self.session:
                self.create_session()
            
            # Rotation aléatoire du User-Agent
            user_agents = [
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
                'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0',
                'Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0'
            ]
            
            headers = kwargs.get('headers', {})
            headers['User-Agent'] = random.choice(user_agents)
            kwargs['headers'] = headers
            
            # Effectuer la requête
            response = self.session.request(method, url, timeout=30, **kwargs)
            
            self.logger.debug(f"Requête {method} vers {url}: {response.status_code}")
            return response
            
        except requests.exceptions.Timeout:
            self.logger.warning(f"Timeout pour {url}")
        except requests.exceptions.ConnectionError:
            self.logger.warning(f"Erreur de connexion pour {url}")
        except Exception as e:
            self.logger.error(f"Erreur requête {url}: {e}")
        
        return None
    
    def is_onion_url(self, url: str) -> bool:
        """
        Vérifie si une URL est un service .onion
        
        Args:
            url: URL à vérifier
            
        Returns:
            bool: True si c'est une URL .onion
        """
        return '.onion' in url.lower()
    
    def close(self):
        """Ferme la session Tor"""
        if self.session:
            self.session.close()
            self.logger.info("Session Tor fermée")


def check_tor_installation() -> bool:
    """
    Vérifie si Tor est installé sur le système
    
    Returns:
        bool: True si Tor est installé
    """
    try:
        # Vérifier si tor est dans le PATH
        result = subprocess.run(['which', 'tor'], 
                              capture_output=True, 
                              text=True)
        return result.returncode == 0
    except:
        return False


def start_tor_if_needed() -> bool:
    """
    Démarre Tor si nécessaire
    
    Returns:
        bool: True si Tor est démarré ou déjà en cours
    """
    tor_session = TorSession()
    
    if tor_session.check_tor_connection():
        return True
    
    if not check_tor_installation():
        print("❌ Tor n'est pas installé. Installez-le avec:")
        print("   macOS: brew install tor")
        print("   Ubuntu: sudo apt install tor")
        print("   Arch: sudo pacman -S tor")
        return False
    
    try:
        print("🔄 Démarrage de Tor...")
        subprocess.Popen(['tor'], 
                        stdout=subprocess.DEVNULL, 
                        stderr=subprocess.DEVNULL)
        
        # Attendre que Tor démarre
        for i in range(30):
            time.sleep(2)
            if tor_session.check_tor_connection():
                print("✅ Tor démarré avec succès")
                return True
            print(f"   Attente... ({i+1}/30)")
        
        print("❌ Impossible de démarrer Tor")
        return False
        
    except Exception as e:
        print(f"❌ Erreur lors du démarrage de Tor: {e}")
        return False


if __name__ == "__main__":
    # Test du module
    logging.basicConfig(level=logging.INFO)
    
    print("🕸️ Test du module TorSession")
    
    # Vérifier et démarrer Tor si nécessaire
    if not start_tor_if_needed():
        sys.exit(1)
    
    # Créer une session de test
    tor = TorSession()
    
    if tor.check_tor_connection():
        session = tor.create_session()
        ip = tor.get_tor_ip()
        
        if ip:
            print(f"✅ Connexion Tor réussie - IP: {ip}")
        
        # Test connectivité .onion
        if tor.test_onion_connectivity():
            print("✅ Services .onion accessibles")
        else:
            print("⚠️ Services .onion non accessibles")
    
    tor.close()