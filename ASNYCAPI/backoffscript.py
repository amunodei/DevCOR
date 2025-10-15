import requests
from time import sleep

base_url = 'https://api.discogs.com/'

backoffs = {
    "factor" : 1.3,
    "wait" : 1,
    "max_tries" : 5

}

def get_releases(release_id):
    endpoint = f'/releases/{release_id}'

    print(f'Getting release #{release_id}')

    resp = requests.get(base_url+endpoint)
    resp_code = resp.status_code

    return resp_code

for i in range(0,30):
    tries = 0
    resp_code = 0
    while resp_code != -1:
        if tries < backoffs["max_tries"]:
            resp_code = get_releases(249504)
            if resp_code == 429:

                print(f'429 - Too many requests. Waiting "{backoffs["wait"]}" seconds. ' )

                sleep(backoffs["wait"])

                backoffs["wait"] *= backoffs["factor"]
                tries += 1
            elif resp_code == 200:
                tries = 0
                resp_code = -1
        else:
            print(f"Reached max retry count {tries}")
            resp_code = -1

