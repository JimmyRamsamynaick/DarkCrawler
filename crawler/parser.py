"""
Module de parsing HTML pour DarkCrawler
Analyse et extrait le contenu des pages web avec BeautifulSoup
"""

import re
import logging
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup, Comment
import requests


class WebParser:
    """Parser HTML pour extraire et analyser le contenu des pages web"""
    
    def __init__(self):
        """Initialise le parser"""
        self.logger = logging.getLogger(__name__)
        
        # Balises à ignorer pour le contenu textuel
        self.ignore_tags = {
            'script', 'style', 'meta', 'link', 'noscript', 
            'header', 'footer', 'nav', 'aside'
        }
        
        # Extensions de fichiers à ignorer
        self.ignore_extensions = {
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg',
            '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt',
            '.zip', '.rar', '.tar', '.gz', '.mp3', '.mp4',
            '.avi', '.mov', '.css', '.js', '.ico'
        }
    
    def parse_html(self, html_content: str, base_url: str = "") -> Dict:
        """
        Parse le contenu HTML et extrait les informations
        
        Args:
            html_content: Contenu HTML à parser
            base_url: URL de base pour résoudre les liens relatifs
            
        Returns:
            Dict: Informations extraites de la page
        """
        try:
            soup = BeautifulSoup(html_content, 'lxml')
            
            # Nettoyer le HTML
            self._clean_html(soup)
            
            # Extraire les informations
            result = {
                'title': self._extract_title(soup),
                'text_content': self._extract_text_content(soup),
                'links': self._extract_links(soup, base_url),
                'forms': self._extract_forms(soup),
                'meta_info': self._extract_meta_info(soup),
                'emails': self._extract_emails(soup),
                'phone_numbers': self._extract_phone_numbers(soup),
                'social_links': self._extract_social_links(soup, base_url),
                'images': self._extract_images(soup, base_url),
                'scripts': self._extract_scripts(soup),
                'comments': self._extract_comments(soup)
            }
            
            self.logger.debug(f"Page parsée: {len(result['text_content'])} caractères de texte")
            return result
            
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing HTML: {e}")
            return {}
    
    def _clean_html(self, soup: BeautifulSoup):
        """
        Nettoie le HTML en supprimant les éléments indésirables
        
        Args:
            soup: Objet BeautifulSoup à nettoyer
        """
        # Supprimer les balises indésirables
        for tag_name in self.ignore_tags:
            for tag in soup.find_all(tag_name):
                tag.decompose()
        
        # Supprimer les commentaires HTML
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment.extract()
    
    def _extract_title(self, soup: BeautifulSoup) -> str:
        """
        Extrait le titre de la page
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            str: Titre de la page
        """
        title_tag = soup.find('title')
        if title_tag:
            return title_tag.get_text().strip()
        
        # Fallback sur h1
        h1_tag = soup.find('h1')
        if h1_tag:
            return h1_tag.get_text().strip()
        
        return "Sans titre"
    
    def _extract_text_content(self, soup: BeautifulSoup) -> str:
        """
        Extrait tout le contenu textuel de la page
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            str: Contenu textuel nettoyé
        """
        # Extraire le texte de toutes les balises
        text_content = soup.get_text(separator=' ', strip=True)
        
        # Nettoyer le texte
        text_content = re.sub(r'\s+', ' ', text_content)  # Normaliser les espaces
        text_content = re.sub(r'\n+', '\n', text_content)  # Normaliser les retours à la ligne
        
        return text_content.strip()
    
    def _extract_links(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """
        Extrait tous les liens de la page
        
        Args:
            soup: Objet BeautifulSoup
            base_url: URL de base pour résoudre les liens relatifs
            
        Returns:
            List[Dict]: Liste des liens avec leurs informations
        """
        links = []
        
        for link in soup.find_all('a', href=True):
            href = link['href'].strip()
            
            if not href or href.startswith('#'):
                continue
            
            # Résoudre l'URL relative
            if base_url:
                full_url = urljoin(base_url, href)
            else:
                full_url = href
            
            # Vérifier si c'est un fichier à ignorer
            parsed_url = urlparse(full_url)
            if any(parsed_url.path.lower().endswith(ext) for ext in self.ignore_extensions):
                continue
            
            link_info = {
                'url': full_url,
                'text': link.get_text().strip(),
                'title': link.get('title', ''),
                'is_onion': '.onion' in full_url.lower(),
                'is_external': self._is_external_link(full_url, base_url)
            }
            
            links.append(link_info)
        
        return links
    
    def _extract_forms(self, soup: BeautifulSoup) -> List[Dict]:
        """
        Extrait les formulaires de la page
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            List[Dict]: Liste des formulaires avec leurs champs
        """
        forms = []
        
        for form in soup.find_all('form'):
            form_info = {
                'action': form.get('action', ''),
                'method': form.get('method', 'GET').upper(),
                'fields': []
            }
            
            # Extraire les champs du formulaire
            for field in form.find_all(['input', 'textarea', 'select']):
                field_info = {
                    'type': field.get('type', 'text'),
                    'name': field.get('name', ''),
                    'id': field.get('id', ''),
                    'placeholder': field.get('placeholder', ''),
                    'required': field.has_attr('required')
                }
                
                form_info['fields'].append(field_info)
            
            forms.append(form_info)
        
        return forms
    
    def _extract_meta_info(self, soup: BeautifulSoup) -> Dict:
        """
        Extrait les métadonnées de la page
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            Dict: Métadonnées extraites
        """
        meta_info = {}
        
        # Meta tags standards
        for meta in soup.find_all('meta'):
            name = meta.get('name') or meta.get('property') or meta.get('http-equiv')
            content = meta.get('content')
            
            if name and content:
                meta_info[name.lower()] = content
        
        # Informations spécifiques
        meta_info['charset'] = self._extract_charset(soup)
        meta_info['language'] = self._extract_language(soup)
        
        return meta_info
    
    def _extract_emails(self, soup: BeautifulSoup) -> List[str]:
        """
        Extrait les adresses email de la page
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            List[str]: Liste des emails trouvés
        """
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        text_content = soup.get_text()
        
        emails = re.findall(email_pattern, text_content)
        return list(set(emails))  # Supprimer les doublons
    
    def _extract_phone_numbers(self, soup: BeautifulSoup) -> List[str]:
        """
        Extrait les numéros de téléphone de la page
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            List[str]: Liste des numéros trouvés
        """
        phone_patterns = [
            r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',  # Format US
            r'\b\+\d{1,3}[-.\s]?\d{1,14}\b',       # Format international
            r'\b\(\d{3}\)\s?\d{3}[-.\s]?\d{4}\b'   # Format (xxx) xxx-xxxx
        ]
        
        text_content = soup.get_text()
        phones = []
        
        for pattern in phone_patterns:
            phones.extend(re.findall(pattern, text_content))
        
        return list(set(phones))
    
    def _extract_social_links(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """
        Extrait les liens vers les réseaux sociaux
        
        Args:
            soup: Objet BeautifulSoup
            base_url: URL de base
            
        Returns:
            List[Dict]: Liste des liens sociaux
        """
        social_domains = {
            'facebook.com': 'Facebook',
            'twitter.com': 'Twitter',
            'instagram.com': 'Instagram',
            'linkedin.com': 'LinkedIn',
            'youtube.com': 'YouTube',
            'telegram.org': 'Telegram',
            'discord.gg': 'Discord',
            'reddit.com': 'Reddit'
        }
        
        social_links = []
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(base_url, href) if base_url else href
            
            for domain, platform in social_domains.items():
                if domain in full_url.lower():
                    social_links.append({
                        'platform': platform,
                        'url': full_url,
                        'text': link.get_text().strip()
                    })
                    break
        
        return social_links
    
    def _extract_images(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """
        Extrait les informations sur les images
        
        Args:
            soup: Objet BeautifulSoup
            base_url: URL de base
            
        Returns:
            List[Dict]: Liste des images avec leurs informations
        """
        images = []
        
        for img in soup.find_all('img', src=True):
            src = img['src']
            full_url = urljoin(base_url, src) if base_url else src
            
            image_info = {
                'url': full_url,
                'alt': img.get('alt', ''),
                'title': img.get('title', ''),
                'width': img.get('width', ''),
                'height': img.get('height', '')
            }
            
            images.append(image_info)
        
        return images
    
    def _extract_scripts(self, soup: BeautifulSoup) -> List[str]:
        """
        Extrait les URLs des scripts JavaScript
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            List[str]: Liste des URLs de scripts
        """
        scripts = []
        
        for script in soup.find_all('script', src=True):
            scripts.append(script['src'])
        
        return scripts
    
    def _extract_comments(self, soup: BeautifulSoup) -> List[str]:
        """
        Extrait les commentaires HTML
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            List[str]: Liste des commentaires
        """
        comments = []
        
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = comment.strip()
            if comment_text:
                comments.append(comment_text)
        
        return comments
    
    def _extract_charset(self, soup: BeautifulSoup) -> str:
        """
        Extrait l'encodage de la page
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            str: Encodage détecté
        """
        # Chercher dans les meta tags
        charset_meta = soup.find('meta', attrs={'charset': True})
        if charset_meta:
            return charset_meta['charset']
        
        # Chercher dans content-type
        content_type_meta = soup.find('meta', attrs={'http-equiv': 'content-type'})
        if content_type_meta and content_type_meta.get('content'):
            content = content_type_meta['content']
            charset_match = re.search(r'charset=([^;]+)', content, re.IGNORECASE)
            if charset_match:
                return charset_match.group(1)
        
        return 'utf-8'  # Défaut
    
    def _extract_language(self, soup: BeautifulSoup) -> str:
        """
        Extrait la langue de la page
        
        Args:
            soup: Objet BeautifulSoup
            
        Returns:
            str: Code de langue
        """
        html_tag = soup.find('html')
        if html_tag and html_tag.get('lang'):
            return html_tag['lang']
        
        # Chercher dans les meta tags
        lang_meta = soup.find('meta', attrs={'name': 'language'})
        if lang_meta and lang_meta.get('content'):
            return lang_meta['content']
        
        return 'unknown'
    
    def _is_external_link(self, url: str, base_url: str) -> bool:
        """
        Vérifie si un lien est externe
        
        Args:
            url: URL à vérifier
            base_url: URL de base
            
        Returns:
            bool: True si le lien est externe
        """
        if not base_url:
            return True
        
        try:
            parsed_url = urlparse(url)
            parsed_base = urlparse(base_url)
            
            return parsed_url.netloc != parsed_base.netloc
        except:
            return True
    
    def extract_potential_credentials(self, parsed_data: Dict) -> List[Dict]:
        """
        Recherche des informations potentiellement sensibles
        
        Args:
            parsed_data: Données parsées de la page
            
        Returns:
            List[Dict]: Liste des informations sensibles trouvées
        """
        sensitive_info = []
        text_content = parsed_data.get('text_content', '')
        
        # Patterns pour différents types d'informations
        patterns = {
            'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'username': r'(?i)(?:username|user|login|account)[:=\s]+([^\s\n]+)',
            'password': r'(?i)(?:password|pass|pwd)[:=\s]+([^\s\n]+)',
            'api_key': r'(?i)(?:api[_-]?key|apikey)[:=\s]+([A-Za-z0-9_-]+)',
            'token': r'(?i)(?:token|auth[_-]?token)[:=\s]+([A-Za-z0-9_.-]+)',
            'credit_card': r'\b(?:\d{4}[\s-]?){3}\d{4}\b',
            'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
            'phone': r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b'
        }
        
        for info_type, pattern in patterns.items():
            matches = re.findall(pattern, text_content)
            for match in matches:
                sensitive_info.append({
                    'type': info_type,
                    'value': match if isinstance(match, str) else match[0] if match else '',
                    'context': self._get_context(text_content, match, 50)
                })
        
        return sensitive_info
    
    def _get_context(self, text: str, match: str, context_length: int = 50) -> str:
        """
        Extrait le contexte autour d'une correspondance
        
        Args:
            text: Texte complet
            match: Correspondance trouvée
            context_length: Longueur du contexte de chaque côté
            
        Returns:
            str: Contexte autour de la correspondance
        """
        try:
            match_str = match if isinstance(match, str) else str(match)
            index = text.find(match_str)
            
            if index == -1:
                return ""
            
            start = max(0, index - context_length)
            end = min(len(text), index + len(match_str) + context_length)
            
            context = text[start:end]
            return context.strip()
        except:
            return ""


if __name__ == "__main__":
    # Test du module
    logging.basicConfig(level=logging.INFO)
    
    print("🔍 Test du module WebParser")
    
    # HTML de test
    test_html = """
    <html lang="en">
    <head>
        <title>Test Page</title>
        <meta charset="utf-8">
        <meta name="description" content="Page de test">
    </head>
    <body>
        <h1>Page de Test</h1>
        <p>Contact: admin@example.com</p>
        <p>Username: testuser</p>
        <p>Password: secret123</p>
        <a href="http://example.onion/page1">Lien Onion</a>
        <a href="https://facebook.com/profile">Facebook</a>
        <form method="POST" action="/login">
            <input type="text" name="username" required>
            <input type="password" name="password" required>
        </form>
    </body>
    </html>
    """
    
    parser = WebParser()
    result = parser.parse_html(test_html, "http://test.onion")
    
    print(f"✅ Titre: {result['title']}")
    print(f"✅ Liens trouvés: {len(result['links'])}")
    print(f"✅ Emails trouvés: {result['emails']}")
    print(f"✅ Formulaires: {len(result['forms'])}")
    
    # Test extraction d'informations sensibles
    sensitive = parser.extract_potential_credentials(result)
    print(f"✅ Informations sensibles: {len(sensitive)}")
    
    for info in sensitive:
        print(f"   - {info['type']}: {info['value']}")