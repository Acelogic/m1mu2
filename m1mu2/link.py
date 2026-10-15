"""bench-side link/REPL stub — transport adapters land as hardware answers arrive."""
from . import frame as F
class LoopbackTransport:
    def __init__(self): self.tx = b""
    def send(self, b): self.tx += b
    def recv(self, timeout=0.1):
        out, self.tx = self.tx, b""
        return out
