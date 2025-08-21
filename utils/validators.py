"""
URL Validator Module
Validates and checks URLs for suspicious patterns
"""

import re
from urllib.parse import urlparse, unquote
from typing import List, Tuple, Optional
import ipaddress

class URLValidator:
    """URL validation and analysis"""
    
    def __init__(self):
        # known url shorteners
        self.url_shorteners = [
            'bit.ly', 'tinyurl.com', 'goo.gl', 'ow.ly',
            'short.link', 'rebrand.ly', 't.co', 'buff.ly',
            'is.gd', 'adf.ly', 'bl.ink', 'lnkd.in'
        ]
        
        # suspicious tlds
        self.suspicious_tlds = [
            '.tk', '.ml', '.ga', '.cf', '.click', '.download',
            '.review', '.country', '.kim', '.science', '.work'
        ]
        
        # legitimate domains (for spoofing check)
        self.legitimate_domains = {
            'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.de'],
            'paypal': ['paypal.com', 'paypal.me'],
            'microsoft': ['microsoft.com', 'outlook.com', 'live.com'],
            'google': ['google.com', 'gmail.com', 'googleapis.com'],
            'apple': ['apple.com', 'icloud.com'],
            'facebook': ['facebook.com', 'fb.com'],
            'twitter': ['twitter.com', 'x.com'],
            'linkedin': ['linkedin.com', 'lnkd.in'],
            'netflix': ['netflix.com'],
            'ebay': ['ebay.com']
        }
    
    def is_suspicious(self, url: str) -> bool:
        """
        Check if URL is suspicious
        Returns True if suspicious
        """
        try:
            # decode url
            url = unquote(url)
            parsed = urlparse(url.lower())
            
            # check various indicators
            checks = [
                self._is_url_shortener(parsed.netloc),
                self._has_suspicious_tld(parsed.netloc),
                self._is_ip_address(parsed.netloc),
                self._has_homograph_attack(parsed.netloc),
                self._has_subdomain_spoofing(parsed.netloc),
                self._has_suspicious_path(parsed.path),
                self._has_multiple_redirects(url)
            ]
            
            return any(checks)
            
        except Exception:
            # error parsing = suspicious
            return True
    
    def _is_url_shortener(self, domain: str) -> bool:
        """Check if domain is url shortener"""
        return any(shortener in domain for shortener in self.url_shorteners)
    
    def _has_suspicious_tld(self, domain: str) -> bool:
        """Check for suspicious TLD"""
        return any(domain.endswith(tld) for tld in self.suspicious_tlds)
    
    def _is_ip_address(self, domain: str) -> bool:
        """Check if domain is IP address"""
        # remove port if present
        domain = domain.split(':')[0]
        try:
            ipaddress.ip_address(domain)
            return True
        except ValueError:
            return False
    
    def _has_homograph_attack(self, domain: str) -> bool:
        """Check for homograph attacks"""
        # common substitutions
        substitutions = [
            ('0', 'o'), ('o', '0'),
            ('1', 'l'), ('l', '1'), ('1', 'i'),
            ('rn', 'm'), ('vv', 'w')
        ]
        
        # check each legitimate domain
        for company, legit_domains in self.legitimate_domains.items():
            for legit in legit_domains:
                # check if similar to legitimate
                if self._is_similar_domain(domain, legit, substitutions):
                    return True
        
        return False
    
    def _is_similar_domain(self, domain: str, legitimate: str, 
                          substitutions: List[Tuple]) -> bool:
        """Check if domain is similar to legitimate"""
        # exact match is ok
        if domain == legitimate:
            return False
        
        # remove subdomains for comparison
        domain_parts = domain.split('.')
        legit_parts = legitimate.split('.')
        
        if len(domain_parts) >= 2 and len(legit_parts) >= 2:
            domain_main = domain_parts[-2]
            legit_main = legit_parts[-2]
            
            # check with substitutions
            for old, new in substitutions:
                test_domain = domain_main.replace(old, new)
                if test_domain == legit_main:
                    return True
            
            # check typosquatting (1 char difference)
            if self._levenshtein_distance(domain_main, legit_main) == 1:
                return True
        
        return False
    
    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate edit distance between strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _has_subdomain_spoofing(self, domain: str) -> bool:
        """Check for subdomain spoofing"""
        # look for legitimate domains in subdomains
        parts = domain.split('.')
        if len(parts) > 2:
            subdomains = '.'.join(parts[:-2])
            for company in self.legitimate_domains:
                if company in subdomains:
                    # check if actual domain is not legitimate
                    main_domain = '.'.join(parts[-2:])
                    if main_domain not in self.legitimate_domains[company]:
                        return True
        return False
    
    def _has_suspicious_path(self, path: str) -> bool:
        """Check for suspicious path patterns"""
        suspicious_patterns = [
            r'/[a-f0-9]{32}',  # md5 hash
            r'/verify/[a-z0-9]+/account',
            r'/security/[a-z0-9]+/update',
            r'\.php\?[a-z]+=[a-z0-9]+(&[a-z]+=[a-z0-9]+){2,}',
            r'/\.\./\.\.',  # directory traversal
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, path.lower()):
                return True
        
        return False
    
    def _has_multiple_redirects(self, url: str) -> bool:
        """Check for multiple redirects"""
        # count redirect parameters
        redirect_params = ['url=', 'redirect=', 'goto=', 'dest=', 'target=']
        count = sum(param in url.lower() for param in redirect_params)
        return count >= 2
    
    def get_domain_info(self, url: str) -> dict:
        """Get detailed domain information"""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()
            
            return {
                'domain': domain,
                'is_https': parsed.scheme == 'https',
                'has_port': ':' in domain,
                'path_depth': len([p for p in parsed.path.split('/') if p]),
                'has_query': bool(parsed.query),
                'is_shortened': self._is_url_shortener(domain),
                'is_ip': self._is_ip_address(domain)
            }
        except:
            return {}