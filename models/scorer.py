"""
Risk Scorer Module
Calculates phishing risk scores from multiple signals
"""

from typing import Dict, List

class RiskScorer:
    """Risk score calculation"""
    
    def __init__(self):
        # weight configuration
        self.weights = {
            'gpt_score': 0.4,
            'pattern_matches': 0.25,
            'url_suspicious': 0.2,
            'sender_trust': 0.15
        }
        
        # trusted domains
        self.trusted_domains = [
            'gmail.com', 'outlook.com', 'yahoo.com',
            'amazon.com', 'microsoft.com', 'google.com',
            'apple.com', 'paypal.com', 'ebay.com'
        ]
    
    def calculate(self, gpt_score: int, pattern_matches: int,
                 suspicious_urls: int, parsed_data: Dict) -> int:
        """
        Calculate final risk score
        Returns score 0-100
        """
        scores = {}
        
        # gpt component
        scores['gpt'] = gpt_score * self.weights['gpt_score']
        
        # pattern component (max 100)
        pattern_score = min(pattern_matches * 15, 100)
        scores['patterns'] = pattern_score * self.weights['pattern_matches']
        
        # url component
        url_score = min(suspicious_urls * 30, 100)
        scores['urls'] = url_score * self.weights['url_suspicious']
        
        # sender trust component
        sender_score = self._calculate_sender_trust(parsed_data.get('sender', ''))
        scores['sender'] = sender_score * self.weights['sender_trust']
        
        # additional factors
        bonus = self._calculate_bonus_factors(parsed_data)
        
        # final score
        final_score = sum(scores.values()) + bonus
        
        # ensure 0-100 range
        return max(0, min(100, int(final_score)))
    
    def _calculate_sender_trust(self, sender: str) -> int:
        """Calculate sender trust score"""
        sender_lower = sender.lower()
        
        # check trusted domains
        for domain in self.trusted_domains:
            if f'@{domain}' in sender_lower:
                # verify not spoofed
                if sender_lower.count('@') == 1:
                    return 0  # trusted
        
        # suspicious indicators
        suspicious_score = 0
        
        # no domain
        if '@' not in sender:
            suspicious_score += 50
        
        # multiple @ symbols
        if sender.count('@') > 1:
            suspicious_score += 30
        
        # numbers in domain
        if '@' in sender:
            domain = sender.split('@')[-1]
            if any(c.isdigit() for c in domain.split('.')[0]):
                suspicious_score += 20
        
        # suspicious keywords
        suspicious_keywords = ['security', 'alert', 'verify', 'suspend']
        for keyword in suspicious_keywords:
            if keyword in sender_lower:
                suspicious_score += 15
        
        return min(suspicious_score, 100)
    
    def _calculate_bonus_factors(self, parsed_data: Dict) -> int:
        """Calculate additional risk factors"""
        bonus = 0
        
        # attachment check
        attachments = parsed_data.get('attachments', [])
        dangerous_extensions = ['.exe', '.zip', '.scr', '.vbs', '.js']
        for attachment in attachments:
            if any(attachment.lower().endswith(ext) for ext in dangerous_extensions):
                bonus += 20
        
        # time factors
        if parsed_data.get('sent_at_odd_hour', False):
            bonus += 5
        
        # reply-to mismatch
        if parsed_data.get('reply_to_mismatch', False):
            bonus += 15
        
        # external images
        if parsed_data.get('external_images_count', 0) > 3:
            bonus += 10
        
        return bonus
    
    def get_risk_factors(self, score: int, parsed_data: Dict) -> List[str]:
        """Get list of risk factors"""
        factors = []
        
        if score > 80:
            factors.append("Very high phishing probability")
        elif score > 60:
            factors.append("High phishing probability")
        elif score > 40:
            factors.append("Moderate phishing risk")
        else:
            factors.append("Low phishing risk")
        
        # specific factors
        if parsed_data.get('suspicious_urls'):
            factors.append("Contains suspicious URLs")
        
        if parsed_data.get('sender_spoofed'):
            factors.append("Sender appears spoofed")
        
        if parsed_data.get('urgency_detected'):
            factors.append("Uses urgency tactics")
        
        return factors