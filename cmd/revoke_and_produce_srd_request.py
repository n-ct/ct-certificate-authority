import requests

url = 'http://localhost:6000/ct/v1/revoke-and-produce-srd'
#url = 'http://localhost:6966/ct/v1/revoke-and-produce-srd'
params = {
    'PercentRevoked': 10,
    'TotalCerts': 10000000
}
r = requests.get(url=url, json=params)
print(r.text)
