import requests
from bs4 import BeautifulSoup
import datetime
import database

def scan_target(url):
    results = []
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, 'html.parser')
        forms = soup.find_all('form')
        
        # SQL Injection Payload Check
        sqli_payload = "' OR 1=1 --"
        # XSS Payload Check
        xss_payload = "<script>alert('XSS')</script>"
        
        # Test forms if any exist
        if forms:
            for form in forms:
                action = form.get('action')
                post_url = url if not action else url + action
                
                # Mock Test SQLi
                try:
                    res_sqli = requests.post(post_url, data={'username': sqli_payload, 'password': 'password'}, timeout=5)
                    if "syntax error" in res_sqli.text.lower() or "mysql" in res_sqli.text.lower() or "login successful" in res_sqli.text.lower():
                         results.append(("SQL Injection", f"Form at {post_url} might be vulnerable.", "Vulnerable"))
                    else:
                         results.append(("SQL Injection", f"Form at {post_url} tested.", "Safe"))
                except:
                     pass

                # Mock Test XSS
                try:
                    res_xss = requests.post(post_url, data={'search': xss_payload}, timeout=5)
                    if xss_payload in res_xss.text:
                         results.append(("Cross-Site Scripting (XSS)", f"Form at {post_url} reflects input.", "Vulnerable"))
                    else:
                         results.append(("Cross-Site Scripting (XSS)", f"Form at {post_url} tested.", "Safe"))
                except:
                     pass
        else:
             # Basic URL parameter test (Mock)
             test_url_sqli = f"{url}?id={sqli_payload}"
             try:
                 res = requests.get(test_url_sqli, timeout=5)
                 if "error in your SQL syntax" in res.text:
                     results.append(("SQL Injection", f"URL parameter id might be vulnerable.", "Vulnerable"))
                 else:
                      results.append(("SQL Injection", "Basic GET request tested.", "Safe"))
             except:
                  pass

             test_url_xss = f"{url}?q={xss_payload}"
             try:
                 res = requests.get(test_url_xss, timeout=5)
                 if xss_payload in res.text:
                     results.append(("Cross-Site Scripting (XSS)", f"URL parameter q reflects input.", "Vulnerable"))
                 else:
                     results.append(("Cross-Site Scripting (XSS)", "Basic GET request tested.", "Safe"))
             except:
                  pass

    except requests.exceptions.RequestException as e:
         results.append(("Connection Error", f"Failed to connect to {url}: {e}", "Error"))

    # Save results to DB
    conn = database.get_db_connection()
    c = conn.cursor()
    for res in results:
        c.execute(
            "INSERT INTO scan_reports (timestamp, url, vulnerability_type, details, status) VALUES (?, ?, ?, ?, ?)",
            (timestamp, url, res[0], res[1], res[2])
        )
    conn.commit()
    conn.close()
    
    return results

if __name__ == "__main__":
    # Test scanner
    res = scan_target("http://127.0.0.1:5000/dummy")
    print(res)
