# -*- coding: utf-8 -*-
"""QMC 系 QQ 音乐加密音频（.mflac / .mgg）解密核心 —— 飞鼠格式 mflac-format.js 的 Python 移植。

支持三类变体（与 Node 版一致）：
  - QMC2 v1（尾部 4 字节 keyLen + key 嵌入）：离线解密
  - QTag（尾部 QTag 标记 + ekey 嵌入）：离线解密
  - musicex（新版，尾部 "musicex" 标记，ekey 不嵌入）：需调 QQ 音乐官方
    GetEVkey 接口用歌曲 ID 换取密钥（仅上传歌曲 ID/文件名，不上传音频内容；
    需要 QQ 音乐登录凭据，从项目内 cookie.py 读取）

解密算法与酷狗 KGG v5 同源（QMC2：ekeyDecrypt + QMC2MAP/QMC2RC4）。
第三方依赖：requests（仅 musicex 联网换密钥/下载用），见 requirements.txt。
"""

import base64
import math
import re
from pathlib import Path

import requests

# ---- 常量 ----
FLAC_HEADER = b"fLaC"
OGG_HEADER = b"OggS"
MUSICEX_MAGIC = b"musicex\x00"
QMC2_ENCV2_PREFIX = b"QQMusic EncV2,Key:"
API_URL = "https://u.y.qq.com/cgi-bin/musicu.fcg"
API_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36")
API_PLATFORM = "20"

# EncV2 双 TEA 密钥
MIX_KEY1 = bytes([0x33, 0x38, 0x36, 0x5A, 0x4A, 0x59, 0x21, 0x40,
                  0x23, 0x2A, 0x24, 0x25, 0x5E, 0x26, 0x29, 0x28])
MIX_KEY2 = bytes([0x2A, 0x2A, 0x23, 0x21, 0x28, 0x23, 0x24, 0x25,
                  0x26, 0x5E, 0x61, 0x31, 0x63, 0x5A, 0x2C, 0x54])

# KGG/QMC2 侧常量（移植自 kgg-format.js）
EKEY_V2_PREFIX = "UVFNdXNpYyBFbmNWMixLZXk6"  # base64("QQMusic EncV2,Key:")
EKEY_V2_KEY1 = bytes([0x33, 0x38, 0x36, 0x5A, 0x4A, 0x59, 0x21, 0x40,
                      0x23, 0x2A, 0x24, 0x25, 0x5E, 0x26, 0x29, 0x28])
EKEY_V2_KEY2 = bytes([0x2A, 0x2A, 0x23, 0x21, 0x28, 0x23, 0x24, 0x25,
                      0x26, 0x5E, 0x61, 0x31, 0x63, 0x5A, 0x2C, 0x54])
QMC_MAP_BOUNDARY = 0x7FFF
QMC_MAP_INDEX_OFFSET = 71214
QMC_MAP_KEY_SIZE = 128
QMC_FIRST_SEGMENT = 0x80
QMC_OTHER_SEGMENT = 0x1400
QMC_RC4_STREAM_SIZE = QMC_OTHER_SEGMENT + 512

TEA_ROUNDS = 16
TEA_DELTA = 0x9E3779B9
TEA_EXPECTED_SUM = (TEA_ROUNDS * TEA_DELTA) & 0xFFFFFFFF


class QmcError(Exception):
    """解密错误，code 与 Node 版错误码一致。"""

    def __init__(self, message, code="MFLAC_DECRYPT_FAILED"):
        super().__init__(message)
        self.code = code
        self.messages = {
            "zhCN": message,
            "enUS": ("Could not fetch the encryption key from QQ Music API."
                     if code == "MFLAC_EKEY_NETWORK" else "MFLAC decryption failed."),
        }


# ---- JS 数值语义辅助 ----
def to_uint32(x):
    return int(x) & 0xFFFFFFFF


def to_int32(x):
    x = to_uint32(x)
    return x if x < 0x80000000 else x - 0x100000000


# ---- 标准腾讯 TEA（移植自 unlock-music qmc_key.ts，EncV2 变体用）----
class TeaCipher:
    def __init__(self, key, rounds=64):
        if len(key) != 16:
            raise ValueError("incorrect key size")
        self.k0 = int.from_bytes(key[0:4], "big")
        self.k1 = int.from_bytes(key[4:8], "big")
        self.k2 = int.from_bytes(key[8:12], "big")
        self.k3 = int.from_bytes(key[12:16], "big")
        self.rounds = rounds

    def decrypt(self, dst, src):
        v0 = int.from_bytes(src[0:4], "big")
        v1 = int.from_bytes(src[4:8], "big")
        s = (TEA_DELTA * self.rounds) / 2.0
        for _ in range(self.rounds // 2):
            v1 = v1 - (to_int32((to_int32(v0) << 4) + self.k2)
                       ^ to_int32(v0 + s)
                       ^ to_int32((to_uint32(v0) >> 5) + self.k3))
            v0 = v0 - (to_int32((to_int32(v1) << 4) + self.k0)
                       ^ to_int32(v1 + s)
                       ^ to_int32((to_uint32(v1) >> 5) + self.k1))
            s -= TEA_DELTA
        dst[0:4] = to_uint32(v0).to_bytes(4, "big")
        dst[4:8] = to_uint32(v1).to_bytes(4, "big")


def decrypt_tencent_tea(in_buf, key):
    """腾讯 TEA-CBC：密文格式 PadLen(1)+Padding(0-7)+Salt(2)+Body+Zero(7)。"""
    if len(in_buf) % 8 != 0:
        raise ValueError("inBuf size not a multiple of the block size")
    if len(in_buf) < 16:
        raise ValueError("inBuf size too small")
    blk = TeaCipher(key, 32)
    tmp_buf = bytearray(8)
    blk.decrypt(tmp_buf, in_buf[0:8])
    n_pad_len = tmp_buf[0] & 0x7
    out_len = len(in_buf) - 1 - n_pad_len - 2 - 7
    if out_len < 0:
        return b""
    out_buf = bytearray(out_len)
    iv_prev = bytearray(8)
    iv_cur = in_buf[0:8]
    pos = 8
    tmp_idx = 1 + n_pad_len

    def crypt_block():
        nonlocal iv_prev, iv_cur, pos, tmp_idx
        iv_prev = iv_cur
        iv_cur = in_buf[pos:pos + 8]
        for j in range(8):
            tmp_buf[j] ^= iv_cur[j]
        blk.decrypt(tmp_buf, tmp_buf)
        pos += 8
        tmp_idx = 0

    i = 1
    while i <= 2:
        if tmp_idx < 8:
            tmp_idx += 1
            i += 1
        else:
            crypt_block()
    out_pos = 0
    while out_pos < out_len:
        if tmp_idx < 8:
            out_buf[out_pos] = tmp_buf[tmp_idx] ^ iv_prev[tmp_idx]
            out_pos += 1
            tmp_idx += 1
        else:
            crypt_block()
    return bytes(out_buf)


def simple_make_key(salt, length):
    key = []
    for i in range(length):
        tmp = math.tan(salt + i * 0.1)
        key.append(0xFF & int(math.fabs(tmp) * 100.0))
    return key


def parse_v1_key_region(key_region):
    """解析 v1 key 区域：新版（EncV2）是 base64 文本，解码后以
    "QQMusic EncV2,Key:" 开头；旧版 key 区域是二进制 ekey（32 字节）。"""
    try:
        decoded = base64.b64decode(key_region.decode("utf8", errors="replace"))
    except Exception:
        return {"type": "legacy"}
    if len(decoded) >= len(QMC2_ENCV2_PREFIX) and decoded[:len(QMC2_ENCV2_PREFIX)] == QMC2_ENCV2_PREFIX:
        out = decrypt_tencent_tea(decoded[len(QMC2_ENCV2_PREFIX):], MIX_KEY1)
        out = decrypt_tencent_tea(out, MIX_KEY2)
        nums = [int(x) for x in out.decode("utf8").split(",")]
        num_buf = bytes(nums)
        text = num_buf.decode("latin1")
        if re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", text):
            ekey = base64.b64decode(text)
        else:
            ekey = num_buf
        return {"type": "encv2", "ekey": ekey}
    return {"type": "legacy"}


def derive_qmc_key(ekey_binary):
    """EncV2 内层派生（unlock-music QmcDeriveKey）：simpleKey(106,8) 交错 + TEA → 流密钥。"""
    simple_key = simple_make_key(106, 8)
    tea_key = bytearray(16)
    for i in range(8):
        tea_key[i << 1] = simple_key[i]
        tea_key[(i << 1) + 1] = ekey_binary[i]
    sub = decrypt_tencent_tea(bytes(ekey_binary[8:]), bytes(tea_key))
    return bytes(ekey_binary[0:8]) + sub


# ---- TEA（tc_tea_cbc_decrypt，kgg ekey 解密用）----
def tea_single_round(value, s, k1, k2):
    a = ((value << 4) + k1) & 0xFFFFFFFF
    b = (value + s) & 0xFFFFFFFF
    c = ((value >> 5) + k2) & 0xFFFFFFFF
    return (a ^ b ^ c) & 0xFFFFFFFF


def tea_ecb_decrypt(value, key):
    y = (value >> 32) & 0xFFFFFFFF
    z = value & 0xFFFFFFFF
    s = TEA_EXPECTED_SUM
    for _ in range(TEA_ROUNDS):
        z = (z - tea_single_round(y, s, key[2], key[3])) & 0xFFFFFFFF
        y = (y - tea_single_round(z, s, key[0], key[1])) & 0xFFFFFFFF
        s = (s - TEA_DELTA) & 0xFFFFFFFF
    return (y << 32) | z


def tea_cbc_decrypt(cipher, key):
    if len(cipher) % 8 != 0 or len(cipher) < 16:
        return b""
    iv1 = 0
    iv2 = 0
    pos = 16

    def decrypt_round(src):
        # 注意：Python 切片是拷贝，JS 的 subarray 是共享视图；这里直接返回解密块字节
        nonlocal iv1, iv2
        iv1_next = (int.from_bytes(src[0:4], "big") << 32) | int.from_bytes(src[4:8], "big")
        iv2_next = tea_ecb_decrypt((iv1_next ^ iv2) & ((1 << 64) - 1), key)
        plain = (iv2_next ^ iv1) & ((1 << 64) - 1)
        iv1 = iv1_next
        iv2 = iv2_next
        return (((plain >> 32) & 0xFFFFFFFF).to_bytes(4, "big")
                + (plain & 0xFFFFFFFF).to_bytes(4, "big"))

    header = decrypt_round(cipher[0:8]) + decrypt_round(cipher[8:16])

    hdr_skip = 1 + (header[0] & 7) + 2  # kFixedSaltLen = 2
    zero_pad = 7
    real_len = len(cipher) - hdr_skip - zero_pad
    if real_len <= 0:
        return b""
    result = bytearray(real_len)

    copy_len = min(16 - hdr_skip, real_len)
    if copy_len > 0:
        result[0:copy_len] = header[hdr_skip:hdr_skip + copy_len]

    out_pos = copy_len
    remaining = real_len - copy_len
    while remaining > 0 and pos + 8 <= len(cipher):
        block = decrypt_round(cipher[pos:pos + 8])
        pos += 8
        take = min(8, remaining)
        result[out_pos:out_pos + take] = block[0:take]
        out_pos += take
        remaining -= take
    return bytes(result)


def ekey_decrypt_v1(ekey):
    result = bytearray(base64.b64decode(ekey))
    if len(result) < 8:
        return b""
    tea_key = [
        (0x69005600 | (result[0] << 16) | result[1]) & 0xFFFFFFFF,
        (0x46003800 | (result[2] << 16) | result[3]) & 0xFFFFFFFF,
        (0x2B002000 | (result[4] << 16) | result[5]) & 0xFFFFFFFF,
        (0x15000B00 | (result[6] << 16) | result[7]) & 0xFFFFFFFF,
    ]
    decrypted = tea_cbc_decrypt(bytes(result[8:]), tea_key)
    return bytes(result[0:8]) + decrypted


def ekey_decrypt(ekey):
    if ekey.startswith(EKEY_V2_PREFIX):
        rest = ekey[len(EKEY_V2_PREFIX):]
        result = tea_cbc_decrypt(rest.encode("utf8"), EKEY_V2_KEY1)
        result = tea_cbc_decrypt(result, EKEY_V2_KEY2)
        return ekey_decrypt_v1(result.decode("utf8"))
    return ekey_decrypt_v1(ekey)


# ---- QMC2 流密码 ----
def qmc2_hash(key):
    h = 1
    for b in key:
        if b == 0:
            continue
        nxt = (h * b) & 0xFFFFFFFF
        if nxt <= h:
            break
        h = nxt
    return h


def qmc2_segment_key(key_hash, segment_id, seed):
    if seed == 0:
        return 0
    return math.floor((key_hash / (seed * (segment_id + 1))) * 100)


def rc4_keystream(key, length):
    n = len(key)
    # JS 用 Uint8Array(n)，s[i]=i 对 n>256 时自动截断为 & 0xFF；Python 需显式处理
    s = [i & 0xFF for i in range(n)]
    j = 0
    for i in range(n):
        j = (j + s[i] + key[i]) % n
        s[i], s[j] = s[j], s[i]
    out = bytearray(length)
    a = 0
    b = 0
    for k in range(length):
        a = (a + 1) % n
        b = (b + s[a]) % n
        s[a], s[b] = s[b], s[a]
        out[k] = s[(s[a] + s[b]) % n]
    return bytes(out)


class QMC2RC4:
    def __init__(self, key):
        self.key = bytes(key)
        self.hash = qmc2_hash(self.key)
        self.stream = rc4_keystream(self.key, QMC_RC4_STREAM_SIZE)

    def decrypt(self, data, offset):
        """原地 XOR 解密/加密（QMC2 加密与解密同函数）。data 为 bytearray。"""
        n = len(self.key)
        pos = 0
        if offset < QMC_FIRST_SEGMENT:
            process_len = min(len(data), QMC_FIRST_SEGMENT - offset)
            for i in range(process_len):
                idx = qmc2_segment_key(self.hash, offset, self.key[offset % n]) % n
                data[i] ^= self.key[idx]
                offset += 1
            pos = process_len
        while pos < len(data):
            segment_idx = offset // QMC_OTHER_SEGMENT
            segment_offset = offset % QMC_OTHER_SEGMENT
            skip_len = qmc2_segment_key(self.hash, segment_idx, self.key[segment_idx % n]) & 0x1FF
            process_len = min(len(data) - pos, QMC_OTHER_SEGMENT - segment_offset)
            for i in range(process_len):
                data[pos + i] ^= self.stream[skip_len + segment_offset + i]
            offset += process_len
            pos += process_len


class QMC2MAP:
    def __init__(self, key):
        n = len(key)
        self.key_map = bytearray(QMC_MAP_KEY_SIZE)
        for i in range(QMC_MAP_KEY_SIZE):
            j = (i * i + QMC_MAP_INDEX_OFFSET) % n
            shift = (j + 4) % 8
            b = key[j]
            self.key_map[i] = ((b << shift) | (b >> shift)) & 0xFF

    def decrypt(self, data, offset):
        for i in range(len(data)):
            idx = offset if offset <= QMC_MAP_BOUNDARY else offset % QMC_MAP_BOUNDARY
            data[i] ^= self.key_map[idx % len(self.key_map)]
            offset += 1


def create_qmc2(ekey):
    key = ekey_decrypt(ekey)
    if not key:
        return None
    if len(key) < 300:
        return QMC2MAP(key)
    return QMC2RC4(key)


# ---- mflac footer 解析与解密 ----
def parse_mflac_footer(buffer):
    if len(buffer) >= 16 and buffer[-8:] == MUSICEX_MAGIC:
        version = int.from_bytes(buffer[-12:-8], "little")
        footer_size = int.from_bytes(buffer[-16:-12], "little")
        if version == 1 and 16 <= footer_size <= len(buffer):
            meta_start = len(buffer) - footer_size
            meta = buffer[meta_start:len(buffer) - 16]
            song_id = int.from_bytes(meta[0:4], "little") if len(meta) > 4 else 0

            def read_utf16(offset, max_bytes):
                if offset + 2 > len(meta):
                    return ""
                end = min(len(meta), offset + max_bytes)
                text = []
                i = offset
                while i + 1 < end:
                    code = int.from_bytes(meta[i:i + 2], "little")
                    if code == 0:
                        break
                    text.append(chr(code))
                    i += 2
                return "".join(text)

            return {
                "type": "musicex",
                "songId": song_id,
                "mediaMid": read_utf16(0x0C, 60),
                "filename": read_utf16(0x48, 68),
                "footerSize": footer_size,
            }
    if len(buffer) >= 12 and int.from_bytes(buffer[-4:], "little") == 0x67615451:  # QTag
        meta_size = int.from_bytes(buffer[-8:-4], "big")
        meta_end = len(buffer) - 8
        meta_start = meta_end - meta_size
        if meta_start >= 0 and meta_size < 0x10000:
            meta = buffer[meta_start:meta_end].decode("utf8", errors="replace")
            parts = meta.split(",")
            if len(parts) >= 2:
                return {"type": "qtag", "ekey": parts[0], "songId": parts[1]}
    key_size = int.from_bytes(buffer[-4:], "little")
    if key_size > 0 and key_size <= 0x400 and key_size < len(buffer) - 8:
        return {"type": "v1", "keySize": key_size}
    return {"type": "unknown"}


def detect_audio_format(buf):
    if len(buf) > 3 and buf[0:4] == FLAC_HEADER:
        return "flac"
    if len(buf) > 3 and buf[0:4] == OGG_HEADER:
        return "ogg"
    if len(buf) > 2 and buf[0:3] == b"ID3":
        return "mp3"
    if len(buf) > 1 and buf[0] == 0xFF and (buf[1] & 0xE0) == 0xE0:
        return "mp3"
    return "unknown"


# 项目内 cookie 配置文件（用户只需改 UIN / QM_KEY 两行）
PROJECT_COOKIE_FILE = Path(__file__).resolve().parent / "cookie.py"


def get_cookie_candidates():
    """凭据候选：仅项目内 cookie.py（显式 --cookie 参数优先于它）。"""
    candidates = []
    if PROJECT_COOKIE_FILE.is_file():
        candidates.append(str(PROJECT_COOKIE_FILE))
    return candidates


def _load_py_cookie(path):
    """读取 .py 配置：UIN / QM_KEY（也兼容小写 uin / qm_keyst）。"""
    namespace = {}
    try:
        exec(compile(path.read_text(encoding="utf8"), str(path), "exec"), namespace)
    except Exception:  # noqa: BLE001 - 配置写错时回退下一个候选
        return None
    uin = namespace.get("UIN") or namespace.get("uin")
    key = namespace.get("QM_KEY") or namespace.get("qm_keyst") or namespace.get("qqmusic_key")
    if uin is None or key is None:
        return None
    return {"uin": str(uin).strip(), "authst": str(key).strip()}


def _load_text_cookie(path):
    """读取文本配置：兼容单行分号（uin=xxx; qm_keyst=yyy）与两行换行分隔。"""
    text = path.read_text(encoding="utf8")
    uin_m = re.search(r"(?:^|[\s;])uin=(\d+)", text)
    auth_m = re.search(r"(?:^|[\s;])(qm_keyst|qqmusic_key)=([^;\s]+)", text)
    if uin_m and auth_m:
        return {"uin": uin_m.group(1), "authst": auth_m.group(2)}
    return None


def load_qq_music_credentials(cookie_path=None):
    """从项目内 cookie.py 读取 QQ 音乐登录凭据（uin + qm_keyst/qqmusic_key）。

    优先级：显式 cookie_path > 项目内 cookie.py。
    .py 文件按 UIN/QM_KEY 变量读取，其余按文本正则读取。
    """
    candidates = []
    if cookie_path:
        candidates.append(cookie_path)
    candidates.extend(get_cookie_candidates())
    for file in candidates:
        if not file:
            continue
        path = Path(file)
        try:
            creds = (_load_py_cookie(path) if path.suffix.lower() == ".py"
                     else _load_text_cookie(path))
        except OSError:
            continue
        if creds:
            return creds
    return None


def fetch_ekey_from_api(creds, filename, song_mid):
    """调 QQ 音乐 GetEVkey 接口获取 ekey（仅传歌曲 ID 与文件名）。
    返回 {"ekey", "purl", "sip"}；ekey 为空 = 该档位当前账号无权限（非网络错误）。"""
    body = {
        "comm": {
            "authst": creds["authst"],
            "ct": "19",
            "cv": "1859",
            "uin": creds["uin"],
            "tme_login_type": "3",
        },
        "req_1": {
            "module": "music.vkey.GetEVkey",
            "method": "CgiGetEVkey",
            "param": {
                "filename": [filename],
                "guid": "10000",
                "songmid": [song_mid],
                "songtype": [1],
                "uin": creds["uin"],
                "loginflag": 1,
                "platform": API_PLATFORM,
                "ctx": 1,
            },
        },
    }
    headers = {
        "User-Agent": API_UA,
        "Referer": "https://y.qq.com/",
    }
    try:
        resp = requests.post(API_URL, json=body, headers=headers, timeout=15)
    except requests.exceptions.Timeout as e:
        raise QmcError("QQ 音乐接口请求超时。", "MFLAC_EKEY_NETWORK") from e
    except requests.exceptions.RequestException as e:
        raise QmcError(f"QQ 音乐接口请求失败：{e}。", "MFLAC_EKEY_NETWORK") from e
    if resp.status_code != 200:
        raise QmcError(f"QQ 音乐接口返回 HTTP {resp.status_code}。", "MFLAC_EKEY_NETWORK")
    try:
        data = resp.json()
    except ValueError as e:
        raise QmcError("QQ 音乐接口返回内容无法解析。", "MFLAC_EKEY_NETWORK") from e
    info = (data.get("req_1") or {}).get("data") or {}
    mid_info = (info.get("midurlinfo") or [{}])[0]
    sip = info.get("sip") or []
    return {"ekey": mid_info.get("ekey") or "", "purl": mid_info.get("purl") or "",
            "sip": sip if isinstance(sip, list) else []}


def musicex_fallback_filenames(media_mid):
    """musicex 无权限时的降档候选（同一首歌的较低音质档位）。"""
    return [
        {"filename": f"F0M{media_mid}.mflac", "label": "FLAC 无损"},
        {"filename": f"O4M{media_mid}.mgg", "label": "OGG 高音质"},
        {"filename": f"M500{media_mid}.mp3", "label": "MP3 320k"},
    ]


def download_musicex_file(purl, sip):
    """下载 QQ 音乐官方 CDN 加密文件（purl 相对路径 + sip 前缀逐个尝试）。"""
    bases = list(dict.fromkeys([b for b in (sip or []) if b]
                               + ["https://dl.stream.qqmusic.qq.com/"]))
    last_error = None
    for base in bases:
        try:
            resp = requests.get(base + purl, timeout=120)
            resp.raise_for_status()
            buf = resp.content
            if len(buf) > 10000:
                return buf
            raise ValueError("下载内容过小")
        except Exception as e:  # noqa: BLE001 - 与 Node 版一致，逐 base 尝试
            last_error = e
    raise QmcError(f"下载加密音频失败：{last_error}。", "MFLAC_EKEY_NETWORK")


def resolve_musicex(creds, footer, original_filename):
    """解析 musicex 密钥：先原档，无权限自动降档下载。
    返回 {"type", "ekey", "fileBuf"?, "audioEnd"?, "note"?}。"""
    first = fetch_ekey_from_api(creds, original_filename, footer["mediaMid"])
    if first["ekey"]:
        return {"type": "direct", "ekey": first["ekey"]}

    for fb in musicex_fallback_filenames(footer["mediaMid"]):
        info = fetch_ekey_from_api(creds, fb["filename"], footer["mediaMid"])
        if not info["ekey"] or not info["purl"]:
            continue
        file_buf = download_musicex_file(info["purl"], info["sip"])
        fb_footer = parse_mflac_footer(file_buf)
        audio_end = (len(file_buf) - fb_footer["footerSize"]
                     if fb_footer["type"] == "musicex" else len(file_buf))
        return {"type": "downloaded", "ekey": info["ekey"], "fileBuf": file_buf,
                "audioEnd": audio_end, "note": fb["label"]}

    raise QmcError(
        "这首歌的所有音质档位（含 FLAC/OGG/MP3 降级）都无在线密钥权限，"
        "可能已下架或需单独购买；请确认账号权限后重试。",
        "MFLAC_EKEY_NETWORK")


def convert_mflac(input_path, cookie_path=None):
    """解密 mflac/mgg 文件，返回 (audio_bytes, format)。

    - v1 / QTag：完全离线
    - musicex：需要 QQ 音乐登录凭据（项目内 cookie.py 或 --cookie 指定）
    """
    buf = Path(input_path).read_bytes()
    if len(buf) < 16:
        raise QmcError("MFLAC 文件不完整。")
    footer = parse_mflac_footer(buf)
    ekey = None
    qmc2 = None
    audio_end = len(buf)
    audio_source = buf

    if footer["type"] == "v1":
        key_start = len(buf) - 4 - footer["keySize"]
        audio_end = key_start
        key_region = buf[key_start:len(buf) - 4]
        parsed = parse_v1_key_region(key_region)
        if parsed["type"] == "encv2":
            final_key = derive_qmc_key(parsed["ekey"])
            qmc2 = QMC2MAP(final_key) if len(final_key) < 300 else QMC2RC4(final_key)
        else:
            ekey = base64.b64encode(key_region).decode("ascii")
    elif footer["type"] == "qtag":
        ekey = footer["ekey"]
        audio_end = len(buf) - 8 - int.from_bytes(buf[-8:-4], "big")
    elif footer["type"] == "musicex":
        audio_end = len(buf) - footer["footerSize"]
        api_filename = footer["filename"]
        if not re.search(r"\.(mgg|mflac|mgg0|mgg1|mggl|mflac0|mflach)$", api_filename, re.I):
            ext = Path(input_path).suffix or ".mflac"
            api_filename = f"{api_filename}{ext}"
        creds = load_qq_music_credentials(cookie_path)
        if not creds:
            raise QmcError(
                "这个 MFLAC 是新版加密（musicex），需要 QQ 音乐登录凭据在线换取密钥；"
                "请修改项目内 cookie.py 的 UIN / QM_KEY 后重试。",
                "MFLAC_EKEY_REQUIRED")
        resolved = resolve_musicex(creds, footer, api_filename)
        if resolved["type"] == "downloaded":
            audio_source = resolved["fileBuf"]
            audio_end = resolved["audioEnd"]
        ekey = resolved["ekey"]
    else:
        raise QmcError("无法识别这个 MFLAC 的加密版本（footer 缺失或格式未知）。")

    if qmc2 is None:
        key = ekey_decrypt(ekey)
        if not key or len(key) < 8:
            raise QmcError("MFLAC 密钥解析失败。")
        qmc2 = create_qmc2(ekey)
        if qmc2 is None:
            raise QmcError("MFLAC 密钥不合法。")

    audio = bytearray(audio_source[0:audio_end])
    qmc2.decrypt(audio, 0)
    fmt = detect_audio_format(audio)
    if fmt == "unknown":
        raise QmcError("MFLAC 解密结果不是可识别的音频格式。")
    return bytes(audio), fmt


# ---- 批量解密 ----
# 批量输入：默认扫描项目内 testdata 文件夹（把下载的加密歌曲放这里）
DEFAULT_INPUT_DIR = Path(__file__).resolve().parent / "testdata"
# 批量输出：无损/原格式输出到 output，MP3 输出到 output_mp3（都自动创建）
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "output"
DEFAULT_MP3_DIR = Path(__file__).resolve().parent / "output_mp3"

# 可识别的加密扩展名
MFLAC_EXTS = {".mflac", ".mgg", ".mgg0", ".mgg1", ".mggl", ".mflac0", ".mflach"}


def collect_audio_files(directory):
    """递归收集目录下所有加密音频文件（.mflac/.mgg 系列，不区分大小写）。"""
    files = []
    for p in sorted(Path(directory).rglob("*")):
        if p.is_file() and p.suffix.lower() in MFLAC_EXTS:
            files.append(p)
    return files
