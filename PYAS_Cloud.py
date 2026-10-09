from PYAS_Diagnostics import log_exception
import os
import time
import threading
import requests


class CloudScanner:
    def __init__(self):
        self.api_host = None
        self.api_key = None
        self.timeout = 30

        self.lock = threading.RLock()
        self.local = threading.local()

    def _get_session(self, api_host, api_key):
        if (
            not hasattr(self.local, "session")
            or getattr(self.local, "host", None) != api_host
            or getattr(self.local, "key", None) != api_key
        ):
            previous = getattr(self.local, "session", None)

            if previous is not None:
                previous.close()

            session = requests.Session()
            session.headers.update({"X-API-Key": api_key, "User-Agent": "PYAS-Engine/1.1"})
            self.local.session = session
            self.local.host = api_host
            self.local.key = api_key

        return self.local.session

    def _request(self, method, endpoint, api_host, api_key, **kwargs):
        session = self._get_session(api_host, api_key)

        try:
            r = session.request(method, f"{api_host}{endpoint}", timeout=self.timeout, **kwargs)

            if r.status_code == 200:
                return r

        except Exception:
            log_exception("PYAS_Cloud.CloudScanner._request:31")
            pass

        return None

    def rescan(self, sha256, api_host, api_key):
        r = self._request("POST", f"/api/rescan/{sha256}", api_host, api_key)
        return r is not None and r.json().get("status") == "success"

    def upload_file(
        self,
        file_path,
        api_host,
        api_key,
        chunk_size=4194304,
        need_rescan=False,
        max_retries=3,
        file_hash=None,
        cancel_event=None,
    ):
        try:
            sha256 = file_hash
            cancel_event = cancel_event or threading.Event()

            if cancel_event.is_set() or not sha256:
                return False, None

            status_req = self._request("GET", f"/api/processing_status/{sha256}", api_host, api_key)

            if cancel_event.is_set():
                return False, sha256

            if status_req:
                current_status = status_req.json().get("status")

                if current_status == "done":
                    if need_rescan:
                        self.rescan(sha256, api_host, api_key)

                    return True, sha256

                elif current_status in ("queued", "processing"):
                    return True, sha256

            file_size = os.path.getsize(file_path)

            if file_size > 104857600:
                return False, sha256

            total_chunks = max(1, (file_size + chunk_size - 1) // chunk_size)
            upload_id = os.urandom(16).hex()

            with open(file_path, "rb") as f:
                for i in range(total_chunks):
                    if cancel_event.is_set():
                        return False, sha256

                    chunk_data = f.read(chunk_size)
                    headers = {
                        "X-Chunk-Index": str(i),
                        "X-Total-Chunks": str(total_chunks),
                        "X-Upload-ID": upload_id,
                    }

                    chunk_success = False

                    for attempt in range(max_retries):
                        if cancel_event.is_set():
                            return False, sha256

                        r = self._request(
                            "POST",
                            "/api/upload",
                            api_host,
                            api_key,
                            files={"file": (os.path.basename(file_path), chunk_data)},
                            headers=headers,
                        )

                        if cancel_event.is_set():
                            return False, sha256

                        if r:
                            if i == total_chunks - 1:
                                try:
                                    resp = r.json()

                                    if "url" in resp:
                                        sha256 = resp.get("url", "").split("/")[-1]
                                except Exception:
                                    log_exception("PYAS_Cloud.CloudScanner.upload_file:89")
                                    pass

                            chunk_success = True
                            break

                        if cancel_event.wait(2**attempt):
                            return False, sha256

                    if not chunk_success:
                        return False, sha256

            return True, sha256
        except Exception:
            log_exception("PYAS_Cloud.CloudScanner.upload_file:101")
            return False, None

    def get_result(self, sha256, api_host, api_key, max_retries=6, interval=10):
        try:
            if not sha256:
                return False

            is_done = False

            for _ in range(max_retries):
                r = self._request("GET", f"/api/processing_status/{sha256}", api_host, api_key)

                if r:
                    st = r.json().get("status", "error")

                    if st == "done":
                        is_done = True
                        break

                    if st in ["error", "failed"]:
                        return False

                time.sleep(interval)

            if not is_done:
                return False

            r = self._request("GET", f"/api/report/{sha256}", api_host, api_key)

            if r:
                data = r.json().get("data", {})
                metadata = data.get("metadata", {})
                label = metadata.get("label", "Unsupport")
                score = metadata.get("score", 0)
                sims = data.get("similar", [])

                is_malicious = "General" in label
                sim_malicious_count = 0
                valid_sim_count = 0

                for s in sims:
                    if s.get("similarity", 0) > 80:
                        valid_sim_count += 1

                        if "General" in s.get("label", ""):
                            sim_malicious_count += 1

                if is_malicious and (
                    valid_sim_count == 0 or sim_malicious_count == valid_sim_count
                ):
                    return f"Malware:WinPE/General.{score}!cl"

        except Exception:
            log_exception("PYAS_Cloud.CloudScanner.get_result:149")
            pass

        return False


class CloudQueueMixin:
    def cloud_check(self, file_path):
        with self.lock_config:
            if not self.pyas_config.get("cloud_switch", False):
                return

            cancel_event = self.cloud_cancel_event

        norm_path = self.norm_path(file_path)

        if not norm_path or cancel_event.is_set():
            return

        cache_key = (os.path.normcase(norm_path), cancel_event)

        with self.lock_file_ops:
            if cache_key in self.cloud_pending:
                return

            self.cloud_pending.add(cache_key)

        self.cloud_queue.put((norm_path, cancel_event))

    def cloud_worker(self):
        while True:
            try:
                file_path, cancel_event = self.cloud_queue.get()
                cache_key = (os.path.normcase(file_path), cancel_event)

                try:
                    self.perform_cloud_scan(file_path, cancel_event)
                finally:
                    with self.lock_file_ops:
                        self.cloud_pending.discard(cache_key)

                    self.cloud_queue.task_done()
            except Exception:
                log_exception("PYAS_Cloud.CloudQueueMixin.cloud_worker:31")
                pass

    def perform_cloud_scan(self, file_path, cancel_event=None):
        was_locked = False

        try:
            with self.lock_config:
                if not self.pyas_config.get("cloud_switch", False):
                    return False

                cancel_event = cancel_event or self.cloud_cancel_event
                api_host, api_key, max_size = (
                    self.pyas_config.get("api_host"),
                    self.pyas_config.get("api_key"),
                    self.pyas_config.get("size", 256 * 1024 * 1024),
                )

            if (
                cancel_event.is_set()
                or not os.path.exists(file_path)
                or not os.path.isfile(file_path)
            ):
                return False

            with self.lock_file_ops:
                if file_path in self.virus_lock:
                    self.lock_file(file_path, False)
                    was_locked = True

            if os.path.getsize(file_path) > max_size:
                if was_locked:
                    self.lock_file(file_path, True)

                return False

            file_hash = self.calc_file_hash(file_path)
            success, sha256 = self.cloud.upload_file(
                file_path, api_host, api_key, file_hash=file_hash, cancel_event=cancel_event
            )

            if was_locked:
                self.lock_file(file_path, True)
                was_locked = False

            if not success and not cancel_event.is_set():
                self.write_log(
                    "WARN", "Cloud API", source=file_path, detail="Failed", success=False
                )

        except Exception as e:
            log_exception("PYAS_Cloud.CloudQueueMixin.perform_cloud_scan:66")
            self.write_log("WARN", "perform_cloud_scan", detail=str(e), success=False)

        finally:
            if was_locked:
                try:
                    self.lock_file(file_path, True)
                except Exception:
                    log_exception("PYAS_Cloud.CloudQueueMixin.perform_cloud_scan:73")
                    pass

        return False
