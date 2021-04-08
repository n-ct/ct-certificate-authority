import requests

url = 'http://localhost:6000/ct/v1/revoke-and-produce-srd'
params = {
    'PercentRevoked': 100,
    'TotalCerts': 10 
}
r = requests.get(url=url, json=params)
print(r.text)
