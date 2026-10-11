from flask import Flask, render_template, request
import re

app = Flask(__name__)

def extract_features(url):
    features = {}
    features['length'] = len(url)
    features['has_at'] = 1 if "@" in url else 0
    features['has_dash'] = 1 if "-" in url else 0
    features['dots_count'] = url.count(".")
    features['has_https'] = 1 if url.startswith("https") else 0
    features['has_ip'] = 1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0
    features['has_suspicious_words'] = 1 if any(word in url.lower() for word in ['login','verify','free','bonus','update','secure']) else 0
    return features

def predict_phishing(url, features):
    # This is a rule-based ML model scoring system (for Final Year Project)
    risk_score = 0
    if features['length'] > 50: risk_score += 2
    if features['has_at']: risk_score += 3
    if features['has_dash']: risk_score += 1
    if features['dots_count'] > 3: risk_score += 2
    if not features['has_https']: risk_score += 2
    if features['has_ip']: risk_score += 3
    if features['has_suspicious_words']: risk_score += 2
    
    is_phishing = risk_score >= 4
    return is_phishing, risk_score, features

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/check', methods=['POST'])
def check():
    url = request.form['url']
    features = extract_features(url)
    is_phishing, risk_score, features = predict_phishing(url, features)
    
    if is_phishing:
        result = f"🚨 DANGER! Phishing Detected (Risk Score: {risk_score}/13)"
        color = "danger"
    else:
        result = f"✅ SAFE! This link looks genuine (Risk Score: {risk_score}/13)"
        color = "safe"
    
    return render_template('index.html', result=result, color=color, url=url, features=features)
    if __name__ == '__main__':
        app.run(host='0.0.0.0', port=10000)
