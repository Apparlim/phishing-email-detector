"""
Pattern Matcher Module
Rule-based pattern detection for common phishing tactics
"""

import re
from typing import List, Dict

class PatternMatcher:
    """Pattern-based phishing detection"""
    
    def __init__(self):
        # init patterns
        self.urgency_words = [
            'urgent', 'immediate', 'expire', 'suspend', 'limit',
            'act now', 'verify now', 'confirm now', 'deadline'
        ]
        
        self.financial_words = [
            'invoice', 'payment', 'refund', 'tax', 'irs', 'bank',
            'credit card', 'account', 'billing', 'charge'
        ]
        
        self.credential_words = [
            'password', 'username', 'login', 'verify', 'confirm',
            'update', 'secure', 'authentication', 'credentials'
        ]
        
        self.suspicious_phrases = [
            'click here immediately',
            'verify your account',
            'suspicious activity',
            'your account will be',
            'confirm your identity',
            'you have won',
            'congratulations you',
            'claim your prize',
            'limited time offer'
        ]
        
        # domain patterns
        self.suspicious_domains = [
            r'bit\.ly', r'tinyurl', r'short\.link',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # ip addresses
            r'[0-9]+-[a-z]+\.com',  # random domains
        ]
        
        self.spoofed_patterns = [
            (r'amaz[o0]n', 'Amazon'),
            (r'micr[o0]s[o0]ft', 'Microsoft'),
            (r'g[o0][o0]gle', 'Google'),
            (r'payp[a@]l', 'PayPal'),
            (r'app[l1]e', 'Apple'),
        ]
    
    def check(self, parsed_email: Dict) -> List[str]:
        """Check email against patterns"""
        threats = []
        
        # check sender
        sender_threats = self._check_sender(parsed_email.get('sender', ''))
        threats.extend(sender_threats)
        
        # check subject
        subject_threats = self._check_subject(parsed_email.get('subject', ''))
        threats.extend(subject_threats)
        
        # check body
        body_threats = self._check_body(parsed_email.get('body', ''))
        threats.extend(body_threats)
        
        # check urls
        url_threats = self._check_urls(parsed_email.get('urls', []))
        threats.extend(url_threats)
        
        return threats
    
    def _check_sender(self, sender: str) -> List[str]:
        """Check sender for spoofing"""
        threats = []
        sender_lower = sender.lower()
        
        # check for spoofed domains
        for pattern, company in self.spoofed_patterns:
            if re.search(pattern, sender_lower):
                if company.lower() not in sender_lower:
                    threats.append(f"⚠️ Possible {company} spoofing detected")
        
        # check for no-reply suspicious
        if 'no-reply' in sender_lower and any(word in sender_lower 
            for word in ['security', 'alert', 'verify']):
            threats.append("Suspicious no-reply address")
        
        # check display name tricks
        if '<' in sender and '>' in sender:
            display = sender.split('<')[0].strip()
            actual = sender.split('<')[1].split('>')[0]
            if '@' in display:
                threats.append("Misleading display name")
        
        return threats
    
    def _check_subject(self, subject: str) -> List[str]:
        """Check subject line"""
        threats = []
        subject_lower = subject.lower()
        
        # urgency check
        urgency_count = sum(1 for word in self.urgency_words 
                          if word in subject_lower)
        if urgency_count >= 2:
            threats.append("Multiple urgency indicators in subject")
        
        # all caps check
        if subject.isupper() and len(subject) > 10:
            threats.append("Excessive capitalization")
        
        # special chars
        if subject.count('!') > 2 or subject.count('$') > 1:
            threats.append("Excessive special characters")
        
        return threats
    
    def _check_body(self, body: str) -> List[str]:
        """Check email body"""
        threats = []
        body_lower = body.lower()
        
        # suspicious phrases
        for phrase in self.suspicious_phrases:
            if phrase in body_lower:
                threats.append(f"Suspicious phrase: '{phrase}'")
        
        # credential harvesting
        cred_count = sum(1 for word in self.credential_words 
                        if word in body_lower)
        if cred_count >= 3:
            threats.append("Potential credential harvesting attempt")
        
        # financial scam
        fin_count = sum(1 for word in self.financial_words 
                       if word in body_lower)
        if fin_count >= 3 and 'urgent' in body_lower:
            threats.append("Potential financial scam")
        
        # grammar check (simple)
        typos = self._check_grammar(body)
        if typos > 3:
            threats.append("Multiple grammar/spelling errors")
        
        return threats
    
    def _check_urls(self, urls: List[str]) -> List[str]:
        """Check URLs for suspicious patterns"""
        threats = []
        
        for url in urls:
            url_lower = url.lower()
            
            # url shorteners
            for pattern in self.suspicious_domains[:3]:
                if re.search(pattern, url_lower):
                    threats.append(f"URL shortener detected: {url[:30]}...")
                    break
            
            # ip addresses
            if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                threats.append("Direct IP address URL")
            
            # homograph attack
            for pattern, company in self.spoofed_patterns:
                if re.search(pattern, url_lower):
                    threats.append(f"Possible {company} URL spoofing")
            
            # suspicious tld
            suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
            if any(tld in url_lower for tld in suspicious_tlds):
                threats.append("Suspicious domain extension")
        
        return threats
    
    def _check_grammar(self, text: str) -> int:
        """Simple grammar error detection"""
        errors = 0
        
        # common mistakes
        mistakes = [
            (r'\s{2,}', 'multiple spaces'),
            (r'[a-z]\s+[A-Z]', 'capitalization'),
            (r'\.\s*[a-z]', 'sentence start'),
        ]
        
        for pattern, _ in mistakes:
            errors += len(re.findall(pattern, text))
        
        return min(errors, 10)  # cap at 10