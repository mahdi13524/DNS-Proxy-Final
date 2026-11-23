import time
import math
from collections import OrderedDict

class TTLCache:
    def __init__(self): self.entries = OrderedDict()
    def get(self, key):
        entry = self.entries.get(key)
        if not entry: return None
        ip, deadline = entry
        ttl = math.ceil(deadline - time.monotonic())
        if ttl <= 0:
            self.entries.pop(key, None)
            return None
        self.entries.move_to_end(key)
        return ip, ttl
    def put(self, key, ip, ttl, maximum):
        # maximum == 0 means unlimited; negative values are invalid and never cached.
        if ttl <= 0 or maximum < 0: return
        self.entries[key] = (ip, time.monotonic() + ttl)
        self.entries.move_to_end(key)
        if maximum > 0:
            while len(self.entries) > maximum:
                self.entries.popitem(last=False)
    def snapshot(self):
        """Return live entries without changing FIFO/LRU ordering."""
        now = time.monotonic()
        result = []
        for key, (ip, deadline) in list(self.entries.items()):
            ttl = math.ceil(deadline - now)
            if ttl <= 0:
                self.entries.pop(key, None)
                continue
            result.append({"domain": key, "ip": ip, "ttl": ttl})
        return result

    def count(self):
        return len(self.snapshot())

    def clear(self): self.entries.clear()
