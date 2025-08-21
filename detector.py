#!/usr/bin/env python3
"""
Phishing Email Detector - Main Engine
Analyzes emails for phishing attempts using GPT and pattern matching
"""

import re
import json
import argparse
import sys
from datetime import datetime
from typing import Dict, List, Tuple, Optional
from pathlib import Path
from dataclasses import dataclass
import os
from dotenv import load_dotenv

from models.analyzer import GPTAnalyzer
from models.patterns import PatternMatcher
from models.scorer import RiskScorer
from utils.parser import EmailParser
from utils.validators import URLValidator
from utils.reporter import ReportGenerator

load_dotenv()

@dataclass
class DetectionResult:
    """Stores phishing detection results"""
    score: int
    risk_level: str
    threats: List[str]
    suspicious_urls: List[str]
    analysis: Dict
    timestamp: str
    recommendations: List[str]

class PhishingDetector:
    """Main phishing detection engine"""
    
    def __init__(self, api_key: str = None):
        # init components
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        self.gpt_analyzer = GPTAnalyzer(self.api_key)
        self.pattern_matcher = PatternMatcher()
        self.risk_scorer = RiskScorer()
        self.email_parser = EmailParser()
        self.url_validator = URLValidator()
        self.reporter = ReportGenerator()
        
        # load config
        self.config = self._load_config()
        
    def _load_config(self) -> Dict:
        """Load configuration settings"""
        config_path = Path('config.json')
        if config_path.exists():
            with open(config_path, 'r') as f:
                return json.load(f)
        return self._default_config()
    
    def _default_config(self) -> Dict:
        """Default configuration"""
        return {
            "model": "gpt-4",
            "temperature": 0.3,
            "max_tokens": 500,
            "risk_thresholds": {
                "low": 30,
                "medium": 60,
                "high": 85
            }
        }
    
    def analyze_email(self, sender: str, subject: str, body: str, 
                     headers: Dict = None) -> DetectionResult:
        """
        Analyze email for phishing indicators
        Returns detection result with score and details
        """
        # parse email components
        parsed = self.email_parser.parse(sender, subject, body, headers)
        
        # extract urls
        urls = self._extract_urls(body)
        suspicious_urls = []
        
        # validate urls
        for url in urls:
            if self.url_validator.is_suspicious(url):
                suspicious_urls.append(url)
        
        # pattern matching
        pattern_threats = self.pattern_matcher.check(parsed)
        
        # gpt analysis
        gpt_result = self.gpt_analyzer.analyze(
            sender=sender,
            subject=subject,
            body=body,
            config=self.config
        )
        
        # combine signals
        all_threats = pattern_threats + gpt_result.get('threats', [])
        
        # add url threats
        if suspicious_urls:
            all_threats.append(f"⚠️ Suspicious URL detected: {len(suspicious_urls)} found")
        
        # calculate risk score
        score = self.risk_scorer.calculate(
            gpt_score=gpt_result.get('score', 0),
            pattern_matches=len(pattern_threats),
            suspicious_urls=len(suspicious_urls),
            parsed_data=parsed
        )
        
        # determine risk level
        risk_level = self._get_risk_level(score)
        
        # generate recommendations
        recommendations = self._generate_recommendations(
            score, all_threats, suspicious_urls
        )
        
        return DetectionResult(
            score=score,
            risk_level=risk_level,
            threats=all_threats,
            suspicious_urls=suspicious_urls,
            analysis=gpt_result,
            timestamp=datetime.now().isoformat(),
            recommendations=recommendations
        )
    
    def _extract_urls(self, text: str) -> List[str]:
        """Extract URLs from text"""
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return re.findall(url_pattern, text)
    
    def _get_risk_level(self, score: int) -> str:
        """Determine risk level from score"""
        thresholds = self.config['risk_thresholds']
        if score < thresholds['low']:
            return 'LOW'
        elif score < thresholds['medium']:
            return 'MEDIUM'
        elif score < thresholds['high']:
            return 'HIGH'
        return 'CRITICAL'
    
    def _generate_recommendations(self, score: int, threats: List[str], 
                                 urls: List[str]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        if score > 60:
            recommendations.append("Do not click any links in this email")
            recommendations.append("Verify sender through official channels")
        
        if urls:
            recommendations.append("Hover over links to verify destinations")
        
        if score > 80:
            recommendations.append("Report this email to your security team")
            recommendations.append("Delete this email immediately")
        
        if not recommendations:
            recommendations.append("Email appears safe but remain vigilant")
        
        return recommendations
    
    def batch_analyze(self, email_list: List[Dict]) -> List[DetectionResult]:
        """Analyze multiple emails"""
        results = []
        for email in email_list:
            try:
                result = self.analyze_email(
                    sender=email.get('sender', ''),
                    subject=email.get('subject', ''),
                    body=email.get('body', ''),
                    headers=email.get('headers')
                )
                results.append(result)
            except Exception as e:
                # log error but continue
                print(f"Error analyzing email: {e}")
                continue
        return results
    
    def generate_report(self, result: DetectionResult, format: str = 'json') -> str:
        """Generate analysis report"""
        return self.reporter.generate(result, format)

def main():
    """CLI entry point"""
    parser = argparse.ArgumentParser(description='Phishing Email Detector')
    parser.add_argument('command', choices=['analyze', 'batch'],
                       help='Operation to perform')
    parser.add_argument('--email', type=str, help='Path to email file')
    parser.add_argument('--directory', type=str, help='Directory with emails')
    parser.add_argument('--output', type=str, help='Output file for results')
    
    args = parser.parse_args()
    
    # init detector
    detector = PhishingDetector()
    
    if args.command == 'analyze':
        if not args.email:
            print("Error: --email required for analyze command")
            sys.exit(1)
        
        # read email file
        with open(args.email, 'r') as f:
            content = f.read()
        
        # simple parsing (can be enhanced)
        lines = content.split('\n')
        sender = lines[0] if lines else ''
        subject = lines[1] if len(lines) > 1 else ''
        body = '\n'.join(lines[2:]) if len(lines) > 2 else ''
        
        # analyze
        result = detector.analyze_email(sender, subject, body)
        
        # output results
        print(f"\n{'='*50}")
        print(f"PHISHING DETECTION RESULTS")
        print(f"{'='*50}")
        print(f"Score: {result.score}/100")
        print(f"Risk Level: {result.risk_level}")
        print(f"\nThreats Detected:")
        for threat in result.threats:
            print(f"  • {threat}")
        print(f"\nRecommendations:")
        for rec in result.recommendations:
            print(f"  → {rec}")
        
        # save if output specified
        if args.output:
            report = detector.generate_report(result)
            with open(args.output, 'w') as f:
                f.write(report)
            print(f"\nReport saved to {args.output}")
    
    elif args.command == 'batch':
        if not args.directory:
            print("Error: --directory required for batch command")
            sys.exit(1)
        
        # process directory
        email_files = Path(args.directory).glob('*.txt')
        results = []
        
        for file_path in email_files:
            with open(file_path, 'r') as f:
                content = f.read()
            # parse and analyze
            lines = content.split('\n')
            result = detector.analyze_email(
                sender=lines[0] if lines else '',
                subject=lines[1] if len(lines) > 1 else '',
                body='\n'.join(lines[2:]) if len(lines) > 2 else ''
            )
            results.append({
                'file': str(file_path),
                'score': result.score,
                'risk': result.risk_level
            })
        
        # display summary
        print(f"\nProcessed {len(results)} emails")
        high_risk = [r for r in results if r['risk'] in ['HIGH', 'CRITICAL']]
        print(f"High risk emails: {len(high_risk)}")
        
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"Results saved to {args.output}")

if __name__ == '__main__':
    main()