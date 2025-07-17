import  requests
import json

headers = {
    'accept': 'application/json',
    'Content-Type': 'application/json'
}

payload = {
    "ioc": "dsnetslekito.xyz"
}

url = 'http://127.0.0.1:8000/api/v1/openai'

response = requests.post(url, headers=headers, json=payload)
response.raise_for_status()
response_data = response.json()
print(json.dumps(response_data, indent=4))
