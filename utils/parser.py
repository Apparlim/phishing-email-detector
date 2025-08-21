"""
Email Parser Module
Extracts and structures email components
"""

import re
import email
from typing import Dict, List, Optional
from datetime import datetime
import base64

class EmailParser:
    """Parse and extract email components"""
    
    def parse(self, sender: str, subject: str, body: str, 
             headers: Dict = None) -> Dict:
        """
        Parse email into structured format
        Returns parsed components
        """
        parsed = {
            'sender': sender,
            'subject': subject,
            'body': body,
            'headers': headers or {},
            'urls': self._extract_urls(body),
            'attachments': [],
            'timestamp': datetime.now().isoformat()
        }
        
        # extract sender components
        parsed.update(self._parse_sender(sender))
        
        # extract metadata
        if headers:
            parsed.update(self._parse_headers(headers))
        
        # detect urgency
        parsed['urgency_detected'] = self._detect_urgency(subject + ' ' + body)
        
        # extract attachments info
        parsed['attachments'] = self._extract_attachments(body, headers)
        
        # check time anomalies
        parsed['sent_at_odd_hour'] = self._check_odd_hour(headers)
        
        # reply-to check
        parsed['reply_to_mismatch'] = self._check_reply_to(headers, sender)
        
        # count external images
        parsed['external_images_count'] = self._count_external_images(body)
        
        return parsed
    
    def _parse_sender(self, sender: str) -> Dict:
        """Parse sender address"""
        result = {}
        
        # extract display name and email
        if '<' in sender and '>' in sender:
            display_name = sender.split('<')[0].strip()
            email_addr = sender.split('<')[1].split('>')[0].strip()
            result['sender_display'] = display_name
            result['sender_email'] = email_addr
            
            # check for spoofing
            if '@' in display_name:
                result['sender_spoofed'] = True
        else:
            result['sender_email'] = sender.strip()
            result['sender_display'] = ''
        
        # extract domain
        if '@' in result['sender_email']:
            result['sender_domain'] = result['sender_email'].split('@')[-1]
        
        return result
    
    def _parse_headers(self, headers: Dict) -> Dict:
        """Parse email headers"""
        result = {}
        
        # extract key headers
        result['return_path'] = headers.get('Return-Path', '')
        result['received_spf'] = headers.get('Received-SPF', '')
        result['dkim_signature'] = headers.get('DKIM-Signature', '')
        result['message_id'] = headers.get('Message-ID', '')
        
        # authentication results
        auth_results = headers.get('Authentication-Results', '')
        result['spf_pass'] = 'pass' in auth_results.lower()
        result['dkim_pass'] = 'dkim=pass' in auth_results.lower()
        result['dmarc_pass'] = 'dmarc=pass' in auth_results.lower()
        
        return result
    
    def _extract_urls(self, body: str) -> List[str]:
        """Extract all URLs from body"""
        urls = []
        
        # standard urls
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls.extend(re.findall(url_pattern, body))
        
        # href urls
        href_pattern = r'href=["\']([^"\']+)["\']'
        hrefs = re.findall(href_pattern, body, re.IGNORECASE)
        urls.extend([url for url in hrefs if url.startswith('http')])
        
        # unique urls
        return list(set(urls))
    
    def _detect_urgency(self, text: str) -> bool:
        """Detect urgency indicators"""
        urgency_patterns = [
            r'urgent', r'immediate', r'expire', r'suspend',
            r'act now', r'limit.*time', r'deadline', r'asap',
            r'within \d+ (hours?|days?)', r'account.*lock'
        ]
        
        text_lower = text.lower()
        urgency_count = 0
        
        for pattern in urgency_patterns:
            if re.search(pattern, text_lower):
                urgency_count += 1
        
        return urgency_count >= 2
    
    def _extract_attachments(self, body: str, headers: Dict) -> List[str]:
        """Extract attachment information"""
        attachments = []
        
        # check content-type for attachments
        if headers:
            content_type = headers.get('Content-Type', '')
            if 'multipart' in content_type:
                # simple attachment detection
                attachment_patterns = [
                    r'filename="([^"]+)"',
                    r'name="([^"]+)"'
                ]
                for pattern in attachment_patterns:
                    found = re.findall(pattern, str(headers))
                    attachments.extend(found)
        
        # check body for attachment references
        if 'attachment' in body.lower():
            # extract mentioned files
            file_pattern = r'([a-zA-Z0-9_-]+\.[a-zA-Z]{2,4})'
            files = re.findall(file_pattern, body)
            attachments.extend(files[:5])  # limit to 5
        
        return list(set(attachments))
    
    def _check_odd_hour(self, headers: Dict) -> bool:
        """Check if sent at odd hour"""
        if not headers:
            return False
        
        date_header = headers.get('Date', '')
        if date_header:
            try:
                # parse date
                sent_time = email.utils.parsedate_to_datetime(date_header)
                hour = sent_time.hour
                # odd hours: midnight to 6am
                return 0 <= hour < 6
            except:
                pass
        
        return False
    
    def _check_reply_to(self, headers: Dict, sender: str) -> bool:
        """Check reply-to mismatch"""
        if not headers:
            return False
        
        reply_to = headers.get('Reply-To', '').lower()
        if reply_to and '@' in reply_to and '@' in sender:
            sender_domain = sender.split('@')[-1].lower()
            reply_domain = reply_to.split('@')[-1]
            return sender_domain != reply_domain
        
        return False
    
    def _count_external_images(self, body: str) -> int:
        """Count external images"""
        img_pattern = r'<img[^>]+src=["\']https?://[^"\']+["\']'
        return len(re.findall(img_pattern, body, re.IGNORECASE))