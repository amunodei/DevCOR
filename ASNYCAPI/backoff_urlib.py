import requests
import logging

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

base_url = 'https://api.discogs.com/'

logging.basicConfig(level=logging.DEBUG)

def get_releases(release_id):
    endpoint = f'/releases/{release_id}'

    session = requests.Session()
    retries = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount(base_url, HTTPAdapter(max_retries=retries))

    print(f'Getting release #{release_id}')

    resp = session.get(base_url+endpoint)
    resp_code = resp.status_code

    return resp_code