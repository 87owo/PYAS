import json
import os
import tempfile


def atomic_write_json(path, data):
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(prefix=".pyas-", suffix=".tmp", dir=directory)

    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            descriptor = None

            json.dump(data, stream, indent=4, ensure_ascii=False)

            stream.flush()
            os.fsync(stream.fileno())

        os.replace(temporary_path, path)
    finally:
        if descriptor is not None:
            os.close(descriptor)

        if os.path.exists(temporary_path):
            os.unlink(temporary_path)
