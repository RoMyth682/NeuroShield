import sqlite3

def check_ai_content():
    conn = sqlite3.connect('neuroshield.db')
    cur = conn.cursor()
    
    cur.execute("SELECT id, title, ai_explanation, exploitation_scenario, fix_snippet FROM scan_findings WHERE session_id = 10")
    findings = cur.fetchall()
    
    print(f"Checking AI content for {len(findings)} findings:")
    for f in findings[:3]: # check first few findings
        title = f[1]
        expl = f[2]
        scen = f[3]
        fix = f[4]
        
        print(f"\n--- Finding: {title} ---")
        print(f"AI Explanation (First 100 chars): {str(expl)[:100]}...")
        print(f"Exploitation Scenario (First 100 chars): {str(scen)[:100]}...")
        print(f"Fix Snippet (First 100 chars): {str(fix)[:100]}...")
        
        # Check if fallback was used
        is_fallback = "Review OWASP secure coding guidelines" in str(fix)
        print(f"Status: {'FALLBACK USED' if is_fallback else 'AI WORKED SUCCESSFULLY!'}")
        
    conn.close()

if __name__ == '__main__':
    check_ai_content()
