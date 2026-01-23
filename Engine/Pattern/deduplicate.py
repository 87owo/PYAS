import os, hashlib

####################################################################################################

def calc_sha256(path):
    with open(path, "rb") as f:
        return hashlib.sha256(f.read()).digest()

def dedup_realtime(root):
    seen = set()
    deleted = 0
    for dirpath, _, files in os.walk(root):
        for name in files:
            p = os.path.join(dirpath, name)
            try:
                h = calc_sha256(p)
            except Exception:
                continue
            if h in seen:
                try:
                    os.remove(p)
                    print(p)
                    deleted += 1
                except Exception:
                    pass
            else:
                seen.add(h)
    print(f"deleted {deleted}")

####################################################################################################

if __name__ == "__main__":
    dedup_realtime(input("Input file path: "))
input('Deduplicate Complete')
