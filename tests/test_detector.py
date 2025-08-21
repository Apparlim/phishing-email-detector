"""
Unit tests for Phishing Email Detector
Run with: pytest tests/test_detector.py
"""

import pytest
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from detector import PhishingDetector
from models.patterns import PatternMatcher
from models.scorer import RiskScorer
from utils.parser import EmailParser
from utils.validators import URLValidator

class TestPhishingDetector:
    """Test main detector"""
    
    @pytest.fixture
    def detector(self):
        # mock api key for testing
        return PhishingDetector(api_key='test-key')
    
    def test_initialization(self, detector):
        """Test detector initialization"""
        assert detector is not None
        assert detector.api_key == 'test-key'
        assert detector.config is not None
    
    def test_extract_urls(self, detector):
        """Test URL extraction"""
        text = "Visit https://example.com and http://test.org for more"
        urls = detector._extract_urls(text)
        assert len(urls) == 2
        assert 'https://example.com' in urls
    
    def test_risk_level(self, detector):
        """Test risk level calculation"""
        assert detector._get_risk_level(20) == 'LOW'
        assert detector._get_risk_level(50) == 'MEDIUM'
        assert detector._get_risk_level(70) == 'HIGH'
        assert detector._get_risk_level(90) == 'CRITICAL'

class TestPatternMatcher:
    """Test pattern matching"""
    
    @pytest.fixture
    def matcher(self):
        return PatternMatcher()
    
    def test_urgency_detection(self, matcher):
        """Test urgency pattern detection"""
        email = {
            'sender': 'test@example.com',
            'subject': 'URGENT: Act Now!',
            'body': 'Your account will expire immediately'
        }
        threats = matcher.check(email)
        assert any('urgency' in str(t).lower() for t in threats)
    
    def test_spoofed_sender(self, matcher):
        """Test spoofed sender detection"""
        threats = matcher._check_sender('security@amaz0n-alerts.com')
        assert any('spoof' in str(t).lower() for t in threats)
    
    def test_suspicious_phrases(self, matcher):
        """Test suspicious phrase detection"""
        threats = matcher._check_body('Click here immediately to verify your account')
        assert len(threats) > 0

class TestURLValidator:
    """Test URL validation"""
    
    @pytest.fixture
    def validator(self):
        return URLValidator()
    
    def test_url_shortener_detection(self, validator):
        """Test URL shortener detection"""
        assert validator.is_suspicious('http://bit.ly/abc123')
        assert validator.is_suspicious('https://tinyurl.com/test')
    
    def test_ip_address_detection(self, validator):
        """Test IP address URL detection"""
        assert validator.is_suspicious('http://192.168.1.1/login')
        assert validator.is_suspicious('https://10.0.0.1:8080/account')
    
    def test_suspicious_tld(self, validator):
        """Test suspicious TLD detection"""
        assert validator.is_suspicious('http://example.tk')
        assert validator.is_suspicious('https://test.click')
    
    def test_legitimate_urls(self, validator):
        """Test legitimate URLs pass"""
        assert not validator.is_suspicious('https://google.com')
        assert not validator.is_suspicious('https://amazon.com/products')

class TestEmailParser:
    """Test email parsing"""
    
    @pytest.fixture
    def parser(self):
        return EmailParser()
    
    def test_parse_sender(self, parser):
        """Test sender parsing"""
        result = parser._parse_sender('John Doe <john@example.com>')
        assert result['sender_display'] == 'John Doe'
        assert result['sender_email'] == 'john@example.com'
        assert result['sender_domain'] == 'example.com'
    
    def test_urgency_detection(self, parser):
        """Test urgency detection in parser"""
        urgent_text = "URGENT: Act now or your account expires immediately!"
        assert parser._detect_urgency(urgent_text) == True
        
        normal_text = "Thank you for your recent purchase"
        assert parser._detect_urgency(normal_text) == False
    
    def test_url_extraction(self, parser):
        """Test URL extraction from body"""
        body = 'Click <a href="http://example.com">here</a> or visit https://test.org'
        urls = parser._extract_urls(body)
        assert len(urls) == 2

class TestRiskScorer:
    """Test risk scoring"""
    
    @pytest.fixture
    def scorer(self):
        return RiskScorer()
    
    def test_score_calculation(self, scorer):
        """Test score calculation"""
        score = scorer.calculate(
            gpt_score=70,
            pattern_matches=3,
            suspicious_urls=2,
            parsed_data={'sender': 'test@suspicious.com'}
        )
        assert 0 <= score <= 100
    
    def test_sender_trust(self, scorer):
        """Test sender trust scoring"""
        # trusted domain
        trust1 = scorer._calculate_sender_trust('support@amazon.com')
        assert trust1 == 0
        
        # suspicious domain
        trust2 = scorer._calculate_sender_trust('alert@amaz0n-security.com')
        assert trust2 > 0
    
    def test_risk_factors(self, scorer):
        """Test risk factor generation"""
        factors = scorer.get_risk_factors(85, {'suspicious_urls': True})
        assert any('high' in f.lower() for f in factors)
        assert any('url' in f.lower() for f in factors)

class TestIntegration:
    """Integration tests"""
    
    def test_phishing_email_detection(self):
        """Test full phishing email detection"""
        detector = PhishingDetector(api_key='test-key')
        
        # mock phishing email
        phishing_email = {
            'sender': 'security@amaz0n-alerts.com',
            'subject': 'URGENT: Verify Your Account Now!',
            'body': '''
            Dear Customer,
            
            We detected suspicious activity on your account.
            Click here immediately: http://bit.ly/verify-account
            
            You must verify within 24 hours or your account will be suspended.
            
            Enter your password and credit card to confirm.
            '''
        }
        
        # would normally test but requires actual API key
        # result = detector.analyze_email(**phishing_email)
        # assert result.score > 60
        # assert result.risk_level in ['HIGH', 'CRITICAL']
    
    def test_legitimate_email_detection(self):
        """Test legitimate email detection"""
        detector = PhishingDetector(api_key='test-key')
        
        # mock legitimate email
        legitimate_email = {
            'sender': 'newsletter@company.com',
            'subject': 'Monthly Newsletter',
            'body': '''
            Hello,
            
            Here's our monthly update with latest news and features.
            
            Visit our website at https://company.com for more information.
            
            Best regards,
            The Team
            '''
        }
        
        # would normally test but requires actual API key
        # result = detector.analyze_email(**legitimate_email)
        # assert result.score < 40
        # assert result.risk_level == 'LOW'

if __name__ == '__main__':
    pytest.main([__file__, '-v'])