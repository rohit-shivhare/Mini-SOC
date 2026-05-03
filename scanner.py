import requests

url = "http://example.com"

res = requests.get(url)

if res.status_code == 200:
    print("website is reachable")
else:
    print("website is not responding properly")