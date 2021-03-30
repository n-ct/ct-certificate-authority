import requests

url = 'http://localhost:6000/ct/v1/post-new-revocation-nums'
params = {'RevocationNums': [1, 3]}
#headers = {'Content-type': 'application/json'}
#r = requests.post(url=url, json=params, headers=headers)
r = requests.post(url=url, json=params)
print(r.text)
