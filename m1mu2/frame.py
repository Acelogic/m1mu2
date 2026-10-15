"""pyfire wire framing: COBS + delimiter, seq-numbered RPC frames. Shared constants with THUMB stub."""
import struct

CRC16_POLY = 0x1021
def crc16(data: bytes, crc: int = 0xFFFF) -> int:
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ CRC16_POLY) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc

# ---- COBS (single-packet semantics; frames are externally delimited by 0x00) ----
def cobs_encode(payload: bytes) -> bytes:
    groups = payload.split(b"\x00")
    out = bytearray()
    for g in groups[:-1]:
        assert len(g) <= 254, "frame too long between zeros for simple encoder"
        out.append(len(g) + 1); out += g
    last = groups[-1]
    if len(last) > 254:
        assert False, "oversized tail group"
    if last or len(groups) > 1:
        out.append(len(last) + 1); out += last
    return bytes(out)

def cobs_decode_packet(enc: bytes) -> bytes:
    out = bytearray(); i = 0
    while i < len(enc):
        code = enc[i]
        if code == 0:
            raise ValueError("delimiter inside encoded packet")
        chunk = enc[i + 1:i + code]
        if len(chunk) != code - 1:
            raise ValueError("truncated group")
        out += chunk; i += code
        if code != 0xFF and i < len(enc):
            out += b"\x00"  # implicit terminator between groups
    return bytes(out)

def cobs_decode_stream(stream: bytes):
    """returns (complete_packets, residual_bytes_including_partial_or_leading_garbage_after_last_delim)."""
    pkts, start = [], 0
    while True:
        z = stream.find(b"\x00", start)
        if z == -1:
            return pkts, stream[start:]
        raw = stream[start:z]
        if raw:  # stray delimiters produce empty raw -> ignore spurious
            try:
                pkts.append(cobs_decode_packet(raw))
            except ValueError:
                pass  # resync: drop corrupt packet
        start = z + 1

# frame layout (payload before COBS): magic 'F'(1B) | seq u16 | cmd u8 | status u8 | body...
MAGIC = b"F"
CMD_PING, CMD_SVC_CALL, CMD_BYE = 0x01, 0x02, 0x0F

def build_frame(seq: int, cmd: int, body: bytes = b"", status: int = 0, use_crc: bool = False) -> bytes:
    p = MAGIC + struct.pack("<HBB", seq & 0xFFFF, cmd, status) + body
    if use_crc:
        p += struct.pack("<H", crc16(p))
    return cobs_encode(p) + b"\x00"

def parse_frame(pkt: bytes):
    if len(pkt) < 6 or pkt[:1] != MAGIC:
        return None
    seq, cmd, status = struct.unpack("<HBB", pkt[1:5])
    return {"seq": seq, "cmd": cmd, "status": status, "body": pkt[5:]}

if __name__ == "__main__":
    f = build_frame(7, CMD_PING, b"\xde\xad\xbe\xef")
    assert f.endswith(b"\x00") and b"\x00" not in f[:-1], "COBS invariant broken"
    pk, res = cobs_decode_stream(f)
    fr = parse_frame(pk[0]) or {}
    assert fr.get("seq") == 7 and fr.get("body") == b"\xde\xad\xbe\xef"
    f2 = build_frame(9, CMD_SVC_CALL, struct.pack("<B6I", 0x1D, *[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]))
    fr2 = parse_frame(cobs_decode_stream(f2)[0][0]); assert fr2["cmd"] == 0x02 and len(fr2["body"]) == 25
    stress = bytes(range(0, 40))  # zero-heavy
    f3 = build_frame(1, CMD_PING, stress)
    assert parse_frame(cobs_decode_stream(f3)[0][0])["body"] == stress
    # zero-only edge + residuals
    f4 = build_frame(2, CMD_PING, b"\x00\x00A\x00")
    assert parse_frame(cobs_decode_stream(f4)[0][0])["body"] == b"\x00\x00A\x00"
    pk5, res5 = cobs_decode_stream(f + b"\xde\xad")  # partial tail preserved
    assert len(pk5) == 1 and res5 == b"\xde\xad"
    # crc path
    f6 = build_frame(3, CMD_PING, b"hi", use_crc=True)
    p6 = cobs_decode_stream(f6)[0][0]
    assert crc16(p6[:-2]) == struct.unpack("<H", p6[-2:])[0]
    print("pyfire framing self-test OK")
