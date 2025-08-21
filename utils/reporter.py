"""
Report Generator Module  
Creates formatted analysis reports
"""

import json
from datetime import datetime
from typing import Dict, Any
import html

class ReportGenerator:
    """Generate analysis reports in various formats"""
    
    def generate(self, result: Any, format: str = 'json') -> str:
        """
        Generate report in specified format
        Supports: json, html, text
        """
        if format == 'json':
            return self._generate_json(result)
        elif format == 'html':
            return self._generate_html(result)
        elif format == 'text':
            return self._generate_text(result)
        else:
            return self._generate_json(result)
    
    def _generate_json(self, result: Any) -> str:
        """Generate JSON report"""
        report = {
            'timestamp': result.timestamp,
            'score': result.score,
            'risk_level': result.risk_level,
            'threats': result.threats,
            'suspicious_urls': result.suspicious_urls,
            'recommendations': result.recommendations,
            'analysis': result.analysis
        }
        return json.dumps(report, indent=2)
    
    def _generate_html(self, result: Any) -> str:
        """Generate HTML report"""
        # risk level colors
        color_map = {
            'LOW': '#28a745',
            'MEDIUM': '#ffc107', 
            'HIGH': '#fd7e14',
            'CRITICAL': '#dc3545'
        }
        
        color = color_map.get(result.risk_level, '#6c757d')
        
        html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Phishing Detection Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }}
        .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 10px; }}
        .score {{ font-size: 48px; font-weight: bold; }}
        .risk-level {{ background: {color}; color: white; padding: 10px 20px; border-radius: 5px; display: inline-block; margin: 10px 0; }}
        .section {{ margin: 20px 0; padding: 15px; background: #f8f9fa; border-radius: 5px; }}
        .threat {{ background: #fff3cd; padding: 10px; margin: 5px 0; border-left: 4px solid #ffc107; }}
        .recommendation {{ background: #d1ecf1; padding: 10px; margin: 5px 0; border-left: 4px solid #17a2b8; }}
        .url {{ background: #f8d7da; padding: 10px; margin: 5px 0; border-left: 4px solid #dc3545; word-break: break-all; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Phishing Detection Report</h1>
        <div class="score">{result.score}/100</div>
        <div class="risk-level">{result.risk_level} RISK</div>
        <p>Generated: {result.timestamp}</p>
    </div>
    
    <div class="section">
        <h2>⚠️ Threats Detected ({len(result.threats)})</h2>
        {"".join(f'<div class="threat">{html.escape(threat)}</div>' for threat in result.threats) if result.threats else '<p>No specific threats identified</p>'}
    </div>
    
    <div class="section">
        <h2>🔗 Suspicious URLs ({len(result.suspicious_urls)})</h2>
        {"".join(f'<div class="url">{html.escape(url)}</div>' for url in result.suspicious_urls) if result.suspicious_urls else '<p>No suspicious URLs found</p>'}
    </div>
    
    <div class="section">
        <h2>💡 Recommendations</h2>
        {"".join(f'<div class="recommendation">{html.escape(rec)}</div>' for rec in result.recommendations)}
    </div>
    
    <div class="section">
        <h2>📊 AI Analysis</h2>
        <pre>{json.dumps(result.analysis, indent=2)}</pre>
    </div>
</body>
</html>
"""
        return html_report
    
    def _generate_text(self, result: Any) -> str:
        """Generate text report"""
        lines = []
        lines.append("=" * 60)
        lines.append("PHISHING DETECTION REPORT")
        lines.append("=" * 60)
        lines.append(f"Timestamp: {result.timestamp}")
        lines.append(f"Risk Score: {result.score}/100")
        lines.append(f"Risk Level: {result.risk_level}")
        lines.append("")
        
        lines.append("THREATS DETECTED:")
        lines.append("-" * 40)
        if result.threats:
            for threat in result.threats:
                lines.append(f"• {threat}")
        else:
            lines.append("No specific threats identified")
        lines.append("")
        
        lines.append("SUSPICIOUS URLS:")
        lines.append("-" * 40)
        if result.suspicious_urls:
            for url in result.suspicious_urls:
                lines.append(f"• {url}")
        else:
            lines.append("No suspicious URLs found")
        lines.append("")
        
        lines.append("RECOMMENDATIONS:")
        lines.append("-" * 40)
        for rec in result.recommendations:
            lines.append(f"→ {rec}")
        lines.append("")
        
        lines.append("AI ANALYSIS:")
        lines.append("-" * 40)
        lines.append(json.dumps(result.analysis, indent=2))
        lines.append("=" * 60)
        
        return "\n".join(lines)
    
    def generate_summary(self, results: list) -> str:
        """Generate summary for batch analysis"""
        total = len(results)
        if total == 0:
            return "No emails analyzed"
        
        # calculate stats
        critical = sum(1 for r in results if r.risk_level == 'CRITICAL')
        high = sum(1 for r in results if r.risk_level == 'HIGH')
        medium = sum(1 for r in results if r.risk_level == 'MEDIUM')
        low = sum(1 for r in results if r.risk_level == 'LOW')
        
        avg_score = sum(r.score for r in results) / total
        
        summary = f"""
BATCH ANALYSIS SUMMARY
{'=' * 40}
Total Emails Analyzed: {total}
Average Risk Score: {avg_score:.1f}/100

Risk Distribution:
• CRITICAL: {critical} ({critical/total*100:.1f}%)
• HIGH: {high} ({high/total*100:.1f}%)
• MEDIUM: {medium} ({medium/total*100:.1f}%)
• LOW: {low} ({low/total*100:.1f}%)

Top Threats:
"""
        # count threat frequency
        threat_count = {}
        for result in results:
            for threat in result.threats:
                threat_type = threat.split(':')[0]
                threat_count[threat_type] = threat_count.get(threat_type, 0) + 1
        
        # top threats
        top_threats = sorted(threat_count.items(), key=lambda x: x[1], reverse=True)[:5]
        for threat, count in top_threats:
            summary += f"• {threat}: {count} occurrences\n"
        
        return summary