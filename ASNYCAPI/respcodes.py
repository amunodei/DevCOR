import requests

base_url = 'https://api.discogs.com/'

def get_releases(release_id):
    endpoint = f'/releases/{release_id}'

    print(f'Getting release #{release_id}')

    resp = requests.get(base_url+endpoint)
    print(resp)

for i in range(0,30):
    get_releases(249504)