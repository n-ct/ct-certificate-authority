import requests

url = 'http://localhost:6000/ct/v1/revoke-and-produce-srd'
#url = 'http://localhost:6966/ct/v1/revoke-and-produce-srd'
params = {
    'PercentRevoked': 0,
    'TotalCerts': 100
}
r = requests.get(url=url, json=params)
print(r.text)
