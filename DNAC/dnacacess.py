import os
import requests
from typing import List, Dict

class DNACClient:
    def __init__(self, base_url: str, username: str, password: str, verify: bool = True):
        self.base = base_url.rstrip('/')
        self.auth = (username, password)
        self.session = requests.Session()
        self.verify = verify
        if not verify:
            requests.packages.urllib3.disable_warnings()

    def get_token(self) -> str:
        url = f"{self.base}/dna/system/api/v1/auth/token"
        resp = self.session.post(url, auth=self.auth, verify=self.verify)
        resp.raise_for_status()
        data = resp.json()
        # Cisco DNAC returns token in 'Token'
        return data.get('Token') or data.get('token')

    def get_all_devices(self, page_limit: int = 500) -> List[Dict]:
        token = self.get_token()
        headers = {"x-auth-token": token, "Content-Type": "application/json"}
        devices = []
        offset = 1

        while True:
            params = {"offset": offset, "limit": page_limit}
            url = f"{self.base}/dna/intent/api/v1/network-device"
            resp = self.session.get(url, headers=headers, params=params, verify=self.verify)
            resp.raise_for_status()
            body = resp.json()
            batch = body.get('response') or []
            if not batch:
                break
            devices.extend(batch)
            if len(batch) < page_limit:
                break
            offset += page_limit

        return devices

if __name__ == "__main__":
    # prefer env vars, fallback to hardcoded values
    BASE = os.environ.get("DNAC_BASE", "https://dnac.example.com")
    USER = os.environ.get("DNAC_USER", "admin")
    PASS = os.environ.get("DNAC_PASS", "password")
    VERIFY_SSL = os.environ.get("DNAC_VERIFY", "true").lower() in ("1", "true", "yes")

    client = DNACClient(BASE, USER, PASS, verify=VERIFY_SSL)
    devices = client.get_all_devices()
    print(f"Found {len(devices)} devices")
    for d in devices:
        # common fields: hostname, managementIpAddress, platformId
        print(d.get("hostname"), d.get("managementIpAddress"), d.get("platformId"))