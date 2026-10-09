import heapq
import itertools
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from PYAS_Diagnostics import log_exception


class TaskScheduler:
    def __init__(self, on_overflow, max_pending=2048, max_workers=4):
        self.max_pending = max_pending
        self.max_workers = max_workers
        self.on_overflow = on_overflow

        self.condition = threading.Condition()
        self.pending = {}
        self.heap = []
        self.running = set()
        self.sequence = itertools.count()

        self.overflow = False
        self.closed = False

        self.pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="PYAS.File")

        self.thread = threading.Thread(
            target=self._dispatch, name="PYAS.FileScheduler", daemon=True
        )

        self.thread.start()

    def schedule(self, key, delay, callback, args=(), critical=False):
        with self.condition:
            if self.closed:
                return False

            worker = threading.current_thread().name.startswith("PYAS.File_")

            limit = self.max_pending + (self.max_workers if worker and critical else 0)

            while key not in self.pending and len(self.pending) >= limit:
                if not critical or worker:
                    self.overflow = True
                    self.condition.notify_all()
                    return False

                self.condition.wait()

                if self.closed:
                    return False

            token = next(self.sequence)
            item = (time.monotonic() + max(0, delay), token, key, callback, args)
            self.pending[key] = item
            heapq.heappush(self.heap, item[:3])

            if len(self.heap) > max(64, 2 * len(self.pending)):
                self.heap = [item[:3] for item in self.pending.values()]
                heapq.heapify(self.heap)

            self.condition.notify_all()
            return True

    def cancel(self, predicate=None):
        with self.condition:
            for key in list(self.pending):
                if predicate is None or predicate(key):
                    self.pending.pop(key, None)

            self.heap = [item[:3] for item in self.pending.values()]
            heapq.heapify(self.heap)

            if predicate is None:
                self.overflow = False

            self.condition.notify_all()

    def _dispatch(self):
        while True:
            with self.condition:
                if self.closed:
                    return

                if len(self.running) >= self.max_workers:
                    self.condition.wait()
                    continue

                if (
                    self.overflow
                    and len(self.pending) < max(1, self.max_pending // 2)
                    and "__recovery__" not in self.running
                ):
                    self.overflow = False
                    item = (0, next(self.sequence), "__recovery__", self.on_overflow, ())
                else:
                    blocked = []
                    item = None

                    while self.heap:
                        due, token, key = self.heap[0]
                        current = self.pending.get(key)

                        if current is None or current[1] != token:
                            heapq.heappop(self.heap)
                            continue

                        if key in self.running:
                            blocked.append(heapq.heappop(self.heap))
                            continue

                        if due > time.monotonic():
                            break

                        heapq.heappop(self.heap)
                        item = self.pending.pop(key)
                        break

                    for entry in blocked:
                        heapq.heappush(self.heap, entry)

                    if item is None:
                        self.condition.wait(timeout=0.1 if self.heap else None)
                        continue

                self.running.add(item[2])
                self.condition.notify_all()

            try:
                self.pool.submit(self._run, item)
            except Exception:
                log_exception("TaskScheduler.submit")

                with self.condition:
                    self.running.discard(item[2])
                    self.overflow = True
                    self.condition.wait(timeout=0.5)

    def _run(self, item):
        try:
            with self.condition:
                if self.closed:
                    return

            item[3](*item[4])
        except Exception:
            log_exception("TaskScheduler.callback")
        finally:
            with self.condition:
                self.running.discard(item[2])
                self.condition.notify_all()

    def close(self, wait=False):
        with self.condition:
            self.closed = True
            self.pending.clear()
            self.heap.clear()
            self.condition.notify_all()

        self.thread.join(timeout=1)
        self.pool.shutdown(wait=wait, cancel_futures=True)
