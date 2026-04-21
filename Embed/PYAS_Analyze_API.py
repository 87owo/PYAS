import os, time, uuid, logging, requests, hashlib

from pathlib import Path
from typing import Optional, List, Dict, Any

####################################################################################################

class PYAS_Client:
    def __init__(self, api_key: str, host: str, timeout: int = 30):
        self.base_url = host.rstrip('/')
        self.timeout = timeout
        self.logger = logging.getLogger("PYAS_API")
        self.session = requests.Session()
        self.session.headers.update({"X-API-Key": api_key, "User-Agent": "PYAS-API/1.1"})
        self.logger.info(f"Initialized PYAS API Client targeting {self.base_url}")

    def _request(self, method: str, endpoint: str, **kwargs) -> Optional[requests.Response]:
        self.logger.debug(f"Request: {method} {endpoint}")
        try:
            r = self.session.request(method, f"{self.base_url}{endpoint}", timeout=self.timeout, **kwargs)
            if r.status_code == 200:
                return r

            error_map = {401: "API Key invalid", 402: "Insufficient points", 404: "Not found", 500: "Server Error"}
            self.logger.error(f"[{endpoint}] Failed: {error_map.get(r.status_code, f'HTTP {r.status_code}')}")

        except Exception as e:
            self.logger.error(f"Connection error: {e}")
        return None

####################################################################################################

    def _calculate_sha256(self, path: Path) -> str:
        self.logger.debug(f"Calculating SHA256 for {path}")
        sha256_hash = hashlib.sha256()

        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(1048576), b""):
                sha256_hash.update(byte_block)

        return sha256_hash.hexdigest()

    def upload_file(self, file_path: str, chunk_size: int = 5242880) -> Optional[str]:
        path = Path(file_path)
        if not path.exists():
            self.logger.error(f"File not found: {file_path}")
            return None
        
        file_size = path.stat().st_size
        self.logger.info(f"Initiating upload for {path.name} ({file_size} bytes)")

        if file_size > 536870912:
            self.logger.error(f"File size exceeds 512MB limit: {file_size} bytes")
            return None

        local_sha256 = self._calculate_sha256(path)
        status_req = self._request("GET", f"/api/processing_status/{local_sha256}")
        
        if status_req and status_req.json().get('status') in ['done', 'processing', 'queued']:
            self.logger.info(f"File already exists or processing on server: {local_sha256}")
            return local_sha256

        if file_size > chunk_size:
            return self._upload_chunked(path, chunk_size, file_size)
        return self._upload_standard(path)

####################################################################################################

    def _upload_standard(self, path: Path, max_retries: int = 3) -> Optional[str]:
        self.logger.info(f"Starting standard upload for {path.name}")
        with open(path, 'rb') as f:
            file_data = f.read()

        for attempt in range(max_retries):
            r = self._request("POST", "/api/upload", files={'file': (path.name, file_data)})
            if r and 'url' in r.json():
                sha256 = r.json().get('url', '').split('/')[-1]
                self.logger.info(f"Standard upload successful: {sha256}")
                return sha256

            self.logger.warning(f"Standard upload retry {attempt + 1}/{max_retries}")
            time.sleep(1)
        
        self.logger.error("Standard upload failed after retries")
        return None

    def _upload_chunked(self, path: Path, chunk_size: int, file_size: int, max_retries: int = 3) -> Optional[str]:
        total_chunks = (file_size + chunk_size - 1) // chunk_size
        upload_id = uuid.uuid4().hex
        self.logger.info(f"Starting chunked upload for {path.name} (Chunks: {total_chunks}, ID: {upload_id})")
        
        with open(path, 'rb') as f:
            for i in range(total_chunks):
                chunk_data = f.read(chunk_size)
                headers = {"X-Chunk-Index": str(i), "X-Total-Chunks": str(total_chunks), "X-Upload-ID": upload_id}
                
                chunk_success = False
                for attempt in range(max_retries):
                    r = self._request("POST", "/api/upload", files={'file': (path.name, chunk_data)}, headers=headers)
                    if r:
                        chunk_success = True
                        self.logger.debug(f"Uploaded chunk {i + 1}/{total_chunks}")

                        if i == total_chunks - 1 and 'url' in r.json():
                            sha256 = r.json().get('url', '').split('/')[-1]
                            self.logger.info(f"Chunked upload successful: {sha256}")
                            return sha256

                        break

                    self.logger.warning(f"Chunk upload retry {attempt + 1}/{max_retries} for chunk {i}")
                    time.sleep(1)
                
                if not chunk_success:
                    self.logger.error(f"Failed to upload chunk {i + 1}/{total_chunks}")
                    return None
        return None

####################################################################################################

    def wait_for_analysis(self, sha256: str, interval: int = 5, max_retries: int = 10) -> bool:
        self.logger.info(f"Waiting for analysis completion: {sha256}")
        for attempt in range(max_retries):
            r = self._request("GET", f"/api/processing_status/{sha256}")
            if r:
                status = r.json().get('status')
                self.logger.debug(f"Analysis status: {status}")

                if status == 'done':
                    self.logger.info(f"Analysis completed: {sha256}")
                    return True

                if status in ['missing', 'error', 'failed']:
                    self.logger.error(f"Analysis failed with status: {status}")
                    return False

            time.sleep(interval)
        
        self.logger.error(f"Analysis polling timed out for {sha256}")
        return False

    def get_report(self, sha256: str) -> Optional[Dict[str, Any]]:
        self.logger.info(f"Fetching report for {sha256}")
        r = self._request("GET", f"/api/report/{sha256}")
        if r:
            return r.json()

        self.logger.error(f"Failed to fetch report for {sha256}")
        return None

####################################################################################################

    def rescan(self, sha256: str) -> bool:
        self.logger.info(f"Triggering rescan for {sha256}")
        r = self._request("POST", f"/api/rescan/{sha256}")

        success = bool(r and r.json().get('status') == 'success')
        if success:
            self.logger.info(f"Rescan triggered successfully for {sha256}")
        else:
            self.logger.error(f"Rescan failed for {sha256}")
        return success

    def search_files(self, query: str, limit: int = 50, page: int = 0, snapshot: Optional[str] = None) -> List[Dict[str, Any]]:
        self.logger.info(f"Searching files (Query: '{query}', Limit: {limit}, Page: {page})")
        payload = {'query': query, 'page': page}
        if snapshot:
            payload['snapshot'] = snapshot

        r = self._request("POST", "/api/search_more", data=payload)
        results = r.json().get('results', [])[:limit] if r else []
        self.logger.info(f"Search returned {len(results)} results")
        return results

    def download_sample(self, sha256: str, save_dir: str = "downloads") -> Optional[str]:
        self.logger.info(f"Downloading sample {sha256}")
        os.makedirs(save_dir, exist_ok=True)
        path = os.path.join(save_dir, f"{sha256}.zip")

        r = self._request("GET", f"/api/download/{sha256}", stream=True)
        if r:
            with open(path, 'wb') as f:
                for chunk in r.iter_content(8192):
                    if chunk:
                        f.write(chunk)
            self.logger.info(f"Sample downloaded successfully to {path}")
            return path

        self.logger.error(f"Failed to download sample {sha256}")
        return None

####################################################################################################

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, format='[%(asctime)s] %(levelname)s [%(name)s] - %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    
    API_KEY = ""
    HOST = "https://pyas-security.com/" 
    
    client = PYAS_Client(API_KEY, HOST)
    target_file = r"test.exe"
    
    sha = client.upload_file(target_file)
    if sha and client.wait_for_analysis(sha):
        report = client.get_report(sha)
        if report:
            meta = report.get('data', {}).get('metadata', {})
            logging.info(f"Result: {meta.get('label')} ({meta.get('score')}%)")
            
    for item in client.search_files('date>=2020; ext=exe | dll', limit=3):
        client.download_sample(item['sha256'])
