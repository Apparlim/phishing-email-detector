"""
GPT Analyzer Module
Handles OpenAI GPT integration for phishing detection
"""

import openai
import json
from typing import Dict, List, Optional
import time

class GPTAnalyzer:
    """GPT-based email analysis"""
    
    def __init__(self, api_key: str):
        self.api_key = api_key
        from openai import OpenAI
        self.client = OpenAI(api_key=api_key)
        self.cache = {}  # simple cache
        
    def analyze(self, sender: str, subject: str, body: str, 
                config: Dict) -> Dict:
        """
        Analyze email with GPT
        Returns threats and confidence score
        """
        # check cache
        cache_key = self._get_cache_key(sender, subject, body)
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        # build prompt
        prompt = self._build_prompt(sender, subject, body)
        
        try:
            # call gpt - updated api
            response = self.client.chat.completions.create(
                model=config.get('model', 'gpt-4'),
                messages=[
                    {"role": "system", "content": self._get_system_prompt()},
                    {"role": "user", "content": prompt}
                ],
                temperature=config.get('temperature', 0.3),
                max_tokens=config.get('max_tokens', 500)
            )
            
            # parse response
            result = self._parse_response(response.choices[0].message.content)
            
            # cache result
            self.cache[cache_key] = result
            
            return result
            
        except Exception as e:
            # fallback on error
            return {
                'score': 50,
                'threats': [f'Analysis error: {str(e)}'],
                'confidence': 0.5
            }
    
    def _get_system_prompt(self) -> str:
        """System prompt for GPT"""
        return """You are an expert email security analyst. Analyze emails for phishing indicators.
        
        Return JSON with:
        - score: 0-100 phishing likelihood
        - threats: list of specific threats found
        - indicators: suspicious patterns detected
        - confidence: your confidence level 0-1
        
        Look for:
        - Spoofed sender addresses
        - Urgency/fear tactics
        - Suspicious URLs
        - Grammar/spelling errors
        - Requests for sensitive info
        - Too good to be true offers"""
    
    def _build_prompt(self, sender: str, subject: str, body: str) -> str:
        """Build analysis prompt"""
        return f"""Analyze this email for phishing:
        
From: {sender}
Subject: {subject}

Body:
{body[:1500]}  

Provide detailed phishing analysis in JSON format."""
    
    def _parse_response(self, response: str) -> Dict:
        """Parse GPT response"""
        try:
            # extract json
            start = response.find('{')
            end = response.rfind('}') + 1
            if start >= 0 and end > start:
                json_str = response[start:end]
                return json.loads(json_str)
        except:
            pass
        
        # fallback parsing
        threats = []
        score = 50
        
        # extract threats from text
        if 'suspicious' in response.lower():
            threats.append("Suspicious content detected")
        if 'phishing' in response.lower():
            score = 75
        if 'urgent' in response.lower():
            threats.append("Urgency tactics detected")
        
        return {
            'score': score,
            'threats': threats,
            'confidence': 0.7
        }
    
    def _get_cache_key(self, sender: str, subject: str, body: str) -> str:
        """Generate cache key"""
        content = f"{sender}:{subject}:{body[:200]}"
        return str(hash(content))
