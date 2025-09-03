"""
Web Interface for Phishing Email Detector
Flask-based web application
"""

from flask import Flask, render_template, request, jsonify
import os
from dotenv import load_dotenv
from detector import PhishingDetector, DetectionResult
import json

load_dotenv()

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16mb max

# init detector
detector = PhishingDetector()

@app.route('/')
def index():
    """Main page"""
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Phishing Email Detector</title>
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body { 
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            .container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                padding: 40px;
                width: 90%;
                max-width: 600px;
            }
            h1 {
                color: #333;
                margin-bottom: 10px;
                font-size: 28px;
            }
            .subtitle {
                color: #666;
                margin-bottom: 30px;
            }
            .form-group {
                margin-bottom: 20px;
            }
            label {
                display: block;
                margin-bottom: 5px;
                color: #555;
                font-weight: 500;
            }
            input, textarea {
                width: 100%;
                padding: 12px;
                border: 2px solid #e0e0e0;
                border-radius: 8px;
                font-size: 14px;
                transition: border-color 0.3s;
            }
            input:focus, textarea:focus {
                outline: none;
                border-color: #667eea;
            }
            textarea {
                min-height: 150px;
                resize: vertical;
            }
            button {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                padding: 14px 30px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                width: 100%;
                transition: transform 0.2s;
            }
            button:hover {
                transform: translateY(-2px);
            }
            button:disabled {
                opacity: 0.5;
                cursor: not-allowed;
            }
            #results {
                margin-top: 30px;
                display: none;
            }
            .result-card {
                background: #f8f9fa;
                border-radius: 10px;
                padding: 20px;
                margin-top: 20px;
            }
            .score-display {
                font-size: 48px;
                font-weight: bold;
                text-align: center;
                margin: 20px 0;
            }
            .risk-badge {
                display: inline-block;
                padding: 8px 16px;
                border-radius: 20px;
                color: white;
                font-weight: 600;
                margin: 10px 0;
            }
            .risk-low { background: #28a745; }
            .risk-medium { background: #ffc107; }
            .risk-high { background: #fd7e14; }
            .risk-critical { background: #dc3545; }
            .threat-item {
                background: #fff3cd;
                padding: 10px;
                margin: 5px 0;
                border-left: 4px solid #ffc107;
                border-radius: 4px;
            }
            .recommendation {
                background: #d1ecf1;
                padding: 10px;
                margin: 5px 0;
                border-left: 4px solid #17a2b8;
                border-radius: 4px;
            }
            .loading {
                text-align: center;
                padding: 20px;
                display: none;
            }
            .spinner {
                border: 3px solid #f3f3f3;
                border-top: 3px solid #667eea;
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 0 auto;
            }
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🛡️ Phishing Email Detector</h1>
            <p class="subtitle">AI-powered email security analysis</p>
            
            <form id="analyzeForm">
                <div class="form-group">
                    <label for="sender">Sender Email</label>
                    <input type="text" id="sender" name="sender" placeholder="support@suspicious-site.com" required>
                </div>
                
                <div class="form-group">
                    <label for="subject">Subject Line</label>
                    <input type="text" id="subject" name="subject" placeholder="Urgent: Verify your account" required>
                </div>
                
                <div class="form-group">
                    <label for="body">Email Body</label>
                    <textarea id="body" name="body" placeholder="Dear customer, click here to verify..." required></textarea>
                </div>
                
                <button type="submit">Analyze Email</button>
            </form>
            
            <div class="loading" id="loading">
                <div class="spinner"></div>
                <p style="margin-top: 10px;">Analyzing email...</p>
            </div>
            
            <div id="results"></div>
        </div>
        
        <script>
            document.getElementById('analyzeForm').addEventListener('submit', async (e) => {
                e.preventDefault();
                
                const form = e.target;
                const submitBtn = form.querySelector('button');
                const loading = document.getElementById('loading');
                const results = document.getElementById('results');
                
                // show loading
                submitBtn.disabled = true;
                loading.style.display = 'block';
                results.style.display = 'none';
                
                const data = {
                    sender: form.sender.value,
                    subject: form.subject.value,
                    body: form.body.value
                };
                
                try {
                    const response = await fetch('/analyze', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json',
                        },
                        body: JSON.stringify(data)
                    });
                    
                    const result = await response.json();
                    
                    // display results
                    displayResults(result);
                    
                } catch (error) {
                    alert('Error analyzing email: ' + error.message);
                } finally {
                    submitBtn.disabled = false;
                    loading.style.display = 'none';
                }
            });
            
            function displayResults(result) {
                const results = document.getElementById('results');
                
                const riskClass = result.risk_level.toLowerCase();
                const scoreColor = result.score < 30 ? '#28a745' : 
                                  result.score < 60 ? '#ffc107' :
                                  result.score < 85 ? '#fd7e14' : '#dc3545';
                
                let threatsHtml = '';
                if (result.threats && result.threats.length > 0) {
                    threatsHtml = '<h3>Threats Detected:</h3>';
                    result.threats.forEach(threat => {
                        threatsHtml += `<div class="threat-item">${threat}</div>`;
                    });
                }
                
                let recommendationsHtml = '<h3>Recommendations:</h3>';
                result.recommendations.forEach(rec => {
                    recommendationsHtml += `<div class="recommendation">${rec}</div>`;
                });
                
                results.innerHTML = `
                    <div class="result-card">
                        <h2>Analysis Results</h2>
                        <div class="score-display" style="color: ${scoreColor}">
                            ${result.score}/100
                        </div>
                        <div style="text-align: center;">
                            <span class="risk-badge risk-${riskClass}">${result.risk_level} RISK</span>
                        </div>
                        ${threatsHtml}
                        ${recommendationsHtml}
                    </div>
                `;
                
                results.style.display = 'block';
            }
        </script>
    </body>
    </html>
    '''

@app.route('/analyze', methods=['POST'])
def analyze():
    """Analyze email endpoint"""
    try:
        data = request.json
        
        if not data:
            return jsonify({'error': 'No data provided'}), 400
            
        # basic validation
        if not data.get('sender') or not data.get('body'):
            return jsonify({'error': 'Sender and body are required'}), 400
        
        # analyze
        result = detector.analyze_email(
            sender=data.get('sender', ''),
            subject=data.get('subject', ''),
            body=data.get('body', '')
        )
        
        # convert to dict
        return jsonify({
            'score': result.score,
            'risk_level': result.risk_level,
            'threats': result.threats,
            'suspicious_urls': result.suspicious_urls,
            'recommendations': result.recommendations,
            'timestamp': result.timestamp
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/batch', methods=['POST'])
def batch_analyze():
    """Batch analysis endpoint"""
    try:
        emails = request.json.get('emails', [])
        results = detector.batch_analyze(emails)
        
        # convert results
        output = []
        for result in results:
            output.append({
                'score': result.score,
                'risk_level': result.risk_level,
                'threats': result.threats
            })
        
        return jsonify({'results': output})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
