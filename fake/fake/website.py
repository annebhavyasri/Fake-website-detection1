## simple_detector.py
import re
import os
class Detector:
    def __init__(self):
        self.bad_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq']
        self.suspicious_words = ['login', 'secure', 'verify', 'password', 'bank']
    def check(self, url):
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        print(f"\n🔍 Checking: {url}")
        score = 100
        notes = []
        if url.startswith('https://'):
            notes.append("✅ HTTPS secure")
        else:
            score -= 20
            notes.append("❌ HTTP only")
        if any(tld in url for tld in self.bad_tlds):
            score -= 30
            notes.append("❌ Suspicious TLD")
        if re.search(r'\d+\.\d+\.\d+\.\d+', url):
            score -= 25
            notes.append("❌ IP address used")
        if any(word in url.lower() for word in self.suspicious_words):
            score -= 15
            notes.append("⚠️ Suspicious keywords")
        if '@' in url:
            score -= 20
            notes.append("❌ @ symbol detected")
        if len(url) > 80:
            score -= 10
            notes.append("⚠️ Long URL")
        score = max(0, score)
        if score >= 70:
            result = "✅ LEGIT"
        elif score >= 40:
            result = "⚠️ SUSPICIOUS"
        else:
            result = "❌ PHISHING"
        print(f"Score: {score}/100 - {result}")
        for n in notes:
            print(" ", n)
        return score, result
def main():
    print("🔐 SIMPLE URL DETECTOR")
    print("=" * 30)
    detector = Detector()
    while True:
        url = input("\nEnter URL (or type exit): ").strip()
        if url.lower() == "exit":
            break
        if url:
            detector.check(url)
if __name__ == "__main__":
    main()