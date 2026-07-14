#!/usr/bin/env python3
import os
import time
import json
import random
import socket
import threading
import asyncio
import ssl
import base64
import logging
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import aiohttp
import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# CONFIGURATION
# =============================================================================

class Config:
    MAJOR_LOGIN_URL = "https://loginbp.ggpolarbear.com"
    GUEST_TOKEN_URL = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

# =============================================================================
# PROTOBUF IMPORTS (with fallback)
# =============================================================================

try:
    from Pb2 import MajoRLoGinrEq_pb2, MajoRLoGinrEs_pb2, PorTs_pb2
except ImportError:
    class MajoRLoGinrEq_pb2: pass
    class MajoRLoGinrEs_pb2: pass
    class PorTs_pb2: pass

# =============================================================================
# GLOBALS
# =============================================================================

connected_clients = {}
connected_clients_lock = threading.Lock()

all_targets = set()
all_targets_lock = threading.Lock()

for fname in ["target.txt", "leader.txt"]:
    if not os.path.exists(fname):
        open(fname, "w").close()

def load_targets_from_files():
    with all_targets_lock:
        all_targets.clear()
        if os.path.exists("target.txt"):
            with open("target.txt", "r") as f:
                for line in f:
                    uid = line.strip()
                    if uid and uid.isdigit():
                        all_targets.add(uid)
        if os.path.exists("leader.txt"):
            with open("leader.txt", "r") as f:
                for line in f:
                    uid = line.strip()
                    if uid and uid.isdigit():
                        all_targets.add(uid)
        print(f"[Init] Loaded {len(all_targets)} targets from files")

load_targets_from_files()

spam_running = True

# =============================================================================
# CRYPTO & PROTOCOL FUNCTIONS (unchanged)
# =============================================================================

AES_KEY = Config.AES_KEY
AES_IV = Config.AES_IV
LOGIN_URL = Config.MAJOR_LOGIN_URL
BADGE_VALUES = {"s1": 1048576, "s2": 32768, "s3": 2048, "s4": 64, "s5": 262144}

def EnC_Uid(H):
    e, H = [], int(H)
    while H:
        e.append((H & 0x7F) | (0x80 if H > 0x7F else 0))
        H >>= 7
    return bytes(e).hex()

def EnC_Vr(N):
    if N < 0:
        return b''
    H = []
    while True:
        b = N & 0x7F
        N >>= 7
        if N:
            b |= 0x80
        H.append(b)
        if not N:
            break
    return bytes(H)

def CrEaTe_ProTo(fields):
    def CrEaTe_VarianT(field_number, value):
        field_header = (field_number << 3) | 0
        return EnC_Vr(field_header) + EnC_Vr(value)
    def CrEaTe_LenGTh(field_number, value):
        field_header = (field_number << 3) | 2
        encoded_value = value.encode() if isinstance(value, str) else value
        return EnC_Vr(field_header) + EnC_Vr(len(encoded_value)) + encoded_value
    packet = bytearray()
    for field, value in fields.items():
        if isinstance(value, dict):
            nested = CrEaTe_ProTo(value)
            packet.extend(CrEaTe_LenGTh(field, nested))
        elif isinstance(value, int):
            packet.extend(CrEaTe_VarianT(field, value))
        elif isinstance(value, (str, bytes)):
            packet.extend(CrEaTe_LenGTh(field, value))
    return packet

def EnC_PacKeT(HeX, K, V):
    cipher = AES.new(K, AES.MODE_CBC, V)
    return cipher.encrypt(pad(bytes.fromhex(HeX), 16)).hex()

def DecodE_HeX(H):
    return hex(H)[2:].zfill(2)

def GeneRaTePk(Pk, N, K, V):
    PkEnc = EnC_PacKeT(Pk, K, V)
    _ = DecodE_HeX(len(PkEnc) // 2)
    if len(_) == 2:
        HeadEr = N + "000000"
    elif len(_) == 3:
        HeadEr = N + "00000"
    elif len(_) == 4:
        HeadEr = N + "0000"
    elif len(_) == 5:
        HeadEr = N + "000"
    else:
        HeadEr = N + "000000"
    return bytes.fromhex(HeadEr + _ + PkEnc)

def openroom(K, V):
    fields = {
        1: 2,
        2: {
            1: 1, 2: 15, 3: 5, 4: "[b][c][ffd319]Ⓥ MAFU", 5: "1", 6: 12, 7: 1, 8: 1, 9: 1,
            11: 1, 12: 2, 14: 36981056,
            15: {1: "IDC3", 2: 126, 3: "ME"},
            16: "\u0001\u0003\u0004\u0007\t\n\u000b\u0012\u000f\u000e\u0016\u0019\u001a \u001d",
            18: 2368584, 27: 1, 34: "\u0000\u0001", 40: "en", 48: 1,
            49: {1: 21}, 50: {1: 36981056, 2: 2368584, 5: 2}
        }
    }
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), '0E15', K, V)

def spmroom(K, V, uid):
    fields = {1: 22, 2: {1: int(uid)}}
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), '0E15', K, V)

def Room_Spam_Full(uid, room_id, message, K, V):
    fields = {
        1: 78,
        2: {
            1: int(room_id),
            2: f"[{random.choice(['FF0000','00FF00','FFFF00','FF00FF'])}]{message}",
            3: {2: 1, 3: 1},
            4: 330,
            5: 6000,
            6: 201,
            10: random.randint(902000001, 902050006),
            11: int(uid),
            12: 1,
            15: {1: 1, 2: 32768},
            16: 32768,
            18: {1: 11481904755, 2: 8, 3: b"\x10\x15\x08\x0A\x0B\x13\x0C\x0F\x11\x04\x07\x02\x03\x0D\x0E\x12\x01\x05\x06"},
            31: {1: 1, 2: 32768},
            32: 32768,
            34: {1: int(uid), 2: 8, 3: bytes([15,6,21,8,10,11,19,12,17,4,14,20,7,2,1,5,16,3,13,18])}
        }
    }
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), '0E15', K, V)

# =============================================================================
# WORKING AVATARS - xBunnEr list of working avatar IDs (from app.py)
# =============================================================================

WORKING_AVATARS = [
    902000028, 902000011, 902000015, 902000013, 902000086,
    902000154, 902000127, 902000207, 902000246, 902000305,
    902000338, 902047016, 902049015, 902052006, 902000100,
    902000204, 902052006, 902037031, 902042011, 902053016, 902051013
]

# =============================================================================
# REQUEST JOIN WITH BADGE - UPDATED WITH WORKING AVATARS
# =============================================================================

def request_join_with_badge(target_uid, badge_value, key, iv, region="BD"):
    """Create join request with badge using xBunnEr working avatars (from app.py)"""
    avatar = random.choice(WORKING_AVATARS)
    fields = {
        1: 33,
        2: {
            1: int(target_uid), 2: region.upper(), 3: 1, 4: 1,
            5: bytes([1, 7, 9, 10, 11, 18, 25, 26, 32]),
            6: "TG:[C][B][FF0000] @MAFU", 7: 330, 8: 1000, 10: region.upper(),
            11: bytes([49, 97, 99, 52, 98, 56, 48, 101, 99, 102, 48, 52, 55, 56, 97, 52, 52, 50, 48, 51, 98, 102, 56, 102, 97, 99, 54, 49, 50, 48, 102, 53]),
            12: 1, 13: int(target_uid),
            14: {1: 2203434355, 2: 8, 3: b"\x10\x15\x08\x0A\x0B\x13\x0C\x0F\x11\x04\x07\x02\x03\x0D\x0E\x12\x01\x05\x06"},
            16: 1, 17: 1, 18: 312, 19: 46,
            23: bytes([16, 1, 24, 1]), 24: avatar,  # Working avatar from xBunnEr
            26: {}, 27: {1: 11, 2: 12999994075, 3: 9999},
            28: {}, 31: {1: 1, 2: int(badge_value)},
            32: int(badge_value),
            34: {1: int(target_uid), 2: 8, 3: b"\x0F\x06\x15\x08\x0A\x0B\x13\x0C\x11\x04\x0E\x14\x07\x02\x01\x05\x10\x03\x0D\x12"}
        },
        10: "en", 13: {2: 1, 3: 1}
    }
    proto = CrEaTe_ProTo(fields)
    p_type = '0519' if region.upper() == 'BD' else ('0514' if region.upper() == 'IND' else '0515')
    return GeneRaTePk(proto.hex(), p_type, key, iv)

def OpEnSq(key, iv, region):
    fields = {1: 1, 2: {2: "\u0001", 3: 1, 4: 1, 5: "en", 9: 1, 11: 1, 13: 1, 14: {2: 5756, 6: 11, 8: "1.111.5", 9: 2, 10: 4}}}
    p_type = '0514' if region.lower() == 'ind' else '0519'
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), p_type, key, iv)

def cHSq(num, target_uid, key, iv, region):
    fields = {1: 17, 2: {1: target_uid, 2: 1, 3: num-1, 4: 62, 5: "\u001a", 8: 5, 13: 329}}
    p_type = '0514' if region.lower() == 'ind' else '0519'
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), p_type, key, iv)

def SEnd_InV(num, target_uid, key, iv, region):
    fields = {1: 2, 2: {1: target_uid, 2: region.upper(), 4: num}}
    p_type = '0514' if region.lower() == 'ind' else '0519'
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), p_type, key, iv)

def SEnd_InV_Full(num, target_uid, key, iv, region):
    fields = {
        1: 2,
        2: {
            1: int(target_uid),
            2: region.upper(),
            4: num,
            6: "Join Fast!",
            7: 330,
            8: 1000,
            9: 100,
            13: int(target_uid),
            17: {2: 159, 4: "y[WW", 6: 11, 8: "1.120.2", 9: 3, 10: 1},
            18: 306,
            19: 18,
            24: random.randint(902000001, 902050006),
            27: {1: 11, 2: 12999994075, 3: 9999},
            31: {1: 1, 2: 32768},
            32: 32768,
            34: {1: int(target_uid), 2: 8, 3: b"\x10\x15\x08\x0A\x0B\x13\x0C\x0F\x11\x04\x07\x02\x03\x0D\x0E\x12\x01\x05\x06"}
        }
    }
    p_type = '0514' if region.lower() == 'ind' else '0519'
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), p_type, key, iv)

def ExiT(key, iv):
    fields = {1: 7, 2: {1: 0}}
    return GeneRaTePk(CrEaTe_ProTo(fields).hex(), '0515', key, iv)

# =============================================================================
# SAFE ACTIVATION FUNCTIONS (unchanged)
# =============================================================================

def build_safe_major_login_payload(open_id, access_token):
    """Build proper MajorLogin protobuf as in main.py"""
    major_login = MajoRLoGinrEq_pb2.MajorLogin()
    major_login.event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    major_login.game_name = "free fire"
    major_login.platform_id = 1
    major_login.client_version = "1.126.1"
    major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
    major_login.system_hardware = "Handheld"
    major_login.telecom_operator = "Verizon"
    major_login.network_type = "WIFI"
    major_login.screen_width = 1920
    major_login.screen_height = 1080
    major_login.screen_dpi = "280"
    major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
    major_login.memory = 3003
    major_login.gpu_renderer = "Adreno (TM) 640"
    major_login.gpu_version = "OpenGL ES 3.1 v1.46"
    major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
    major_login.client_ip = "223.191.51.89"
    major_login.language = "en"
    major_login.open_id = open_id
    major_login.open_id_type = "4"
    major_login.device_type = "Handheld"
    major_login.memory_available.version = 55
    major_login.memory_available.hidden_value = 81
    major_login.access_token = access_token
    major_login.platform_sdk_id = 1
    major_login.network_operator_a = "Verizon"
    major_login.network_type_a = "WIFI"
    major_login.client_using_version = "7428b253defc164018c604a1ebbfebdf"
    major_login.external_storage_total = 36235
    major_login.external_storage_available = 31335
    major_login.internal_storage_total = 2519
    major_login.internal_storage_available = 703
    major_login.game_disk_storage_available = 25010
    major_login.game_disk_storage_total = 26628
    major_login.external_sdcard_avail_storage = 32992
    major_login.external_sdcard_total_storage = 36235
    major_login.login_by = 3
    major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
    major_login.reg_avatar = 1
    major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
    major_login.channel_type = 3
    major_login.cpu_type = 2
    major_login.cpu_architecture = "64"
    major_login.client_version_code = "2019116753"
    major_login.graphics_api = "OpenGLES2"
    major_login.supported_astc_bitset = 16383
    major_login.login_open_id_type = 4
    major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
    major_login.loading_time = 13564
    major_login.release_channel = "android"
    major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
    major_login.android_engine_init_flag = 110009
    major_login.if_push = 1
    major_login.is_vpn = 1
    major_login.origin_platform_type = "4"
    major_login.primary_platform_type = "4"
    
    proto_bytes = major_login.SerializeToString()
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(proto_bytes, AES.block_size))
    return encrypted

def parse_safe_major_login_response(response_bytes):
    """Parse MajorLoginRes protobuf to extract token, key, iv, region, url"""
    try:
        res = MajoRLoGinrEs_pb2.MajorLoginRes()
        res.ParseFromString(response_bytes)
        return {
            'token': res.token,
            'key': res.key,
            'iv': res.iv,
            'region': res.region,
            'url': res.url,
            'account_uid': res.account_uid,
            'timestamp': res.timestamp
        }
    except Exception as e:
        print(f"[!] Failed to parse MajorLoginRes: {e}")
        return None

def major_login_safe(access_token, open_id):
    payload = build_safe_major_login_payload(open_id, access_token)
    if not payload:
        return None
        
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Connection': 'Keep-Alive',
    }
    try:
        response = requests.post(Config.MAJOR_LOGIN_URL + "/MajorLogin", headers=headers, data=payload, verify=False, timeout=15)
        if response.status_code == 200 and len(response.content) > 0:
            return response.content
        else:
            return None
    except Exception as e:
        print(f"[!] MajorLogin error: {e}")
        return None

def build_get_login_data_payload(jwt_token, access_token):
    """Build GetLoginData payload (same as acti.py)"""
    try:
        token_payload_base64 = jwt_token.split('.')[1]
        token_payload_base64 += '=' * ((4 - len(token_payload_base64) % 4) % 4)
        decoded_payload = base64.urlsafe_b64decode(token_payload_base64).decode('utf-8')
        payload_dict = json.loads(decoded_payload)
        external_id = payload_dict['external_id']
        signature_md5 = payload_dict['signature_md5']
        
        major_login = MajoRLoGinrEq_pb2.MajorLogin()
        major_login.event_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        major_login.game_name = "free fire"
        major_login.platform_id = 1
        major_login.client_version = "1.126.1"
        major_login.system_software = "Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)"
        major_login.system_hardware = "Handheld"
        major_login.telecom_operator = "Verizon"
        major_login.network_type = "WIFI"
        major_login.screen_width = 1920
        major_login.screen_height = 1080
        major_login.screen_dpi = "280"
        major_login.processor_details = "ARM64 FP ASIMD AES VMH | 2865 | 4"
        major_login.memory = 3003
        major_login.gpu_renderer = "Adreno (TM) 640"
        major_login.gpu_version = "OpenGL ES 3.1 v1.46"
        major_login.unique_device_id = "Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57"
        major_login.client_ip = "223.191.51.89"
        major_login.language = "en"
        major_login.open_id = external_id
        major_login.open_id_type = "4"
        major_login.device_type = "Handheld"
        major_login.memory_available.version = 55
        major_login.memory_available.hidden_value = 81
        major_login.access_token = access_token
        major_login.platform_sdk_id = 1
        major_login.network_operator_a = "Verizon"
        major_login.network_type_a = "WIFI"
        major_login.client_using_version = signature_md5
        major_login.external_storage_total = 36235
        major_login.external_storage_available = 31335
        major_login.internal_storage_total = 2519
        major_login.internal_storage_available = 703
        major_login.game_disk_storage_available = 25010
        major_login.game_disk_storage_total = 26628
        major_login.external_sdcard_avail_storage = 32992
        major_login.external_sdcard_total_storage = 36235
        major_login.login_by = 3
        major_login.library_path = "/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/lib/arm64"
        major_login.reg_avatar = 1
        major_login.library_token = "5b892aaabd688e571f688053118a162b|/data/app/com.dts.freefireth-YPKM8jHEwAJlhpmhDhv5MQ==/base.apk"
        major_login.channel_type = 3
        major_login.cpu_type = 2
        major_login.cpu_architecture = "64"
        major_login.client_version_code = "2019116753"
        major_login.graphics_api = "OpenGLES2"
        major_login.supported_astc_bitset = 16383
        major_login.login_open_id_type = 4
        major_login.analytics_detail = b"FwQVTgUPX1UaUllDDwcWCRBpWAUOUgsvA1snWlBaO1kFYg=="
        major_login.loading_time = 13564
        major_login.release_channel = "android"
        major_login.extra_info = "KqsHTymw5/5GB23YGniUYN2/q47GATrq7eFeRatf0NkwLKEMQ0PK5BKEk72dPflAxUlEBir6Vtey83XqF593qsl8hwY="
        major_login.android_engine_init_flag = 110009
        major_login.if_push = 1
        major_login.is_vpn = 1
        major_login.origin_platform_type = "4"
        major_login.primary_platform_type = "4"
        
        proto_bytes = major_login.SerializeToString()
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv  = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted = cipher.encrypt(pad(proto_bytes, AES.block_size))
        return encrypted
    except Exception as e:
        print(f"[!] Build GetLoginData payload error: {e}")
        return None

def get_login_data_safe(jwt_token, access_token, base_url):
    payload = build_get_login_data_payload(jwt_token, access_token)
    if not payload:
        return False
    url = f"{base_url}/GetLoginData"
    headers = {
        'Authorization': f'Bearer {jwt_token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
        'Connection': 'close',
        'Accept-Encoding': 'gzip, deflate, br',
    }
    try:
        response = requests.post(url, headers=headers, data=payload, verify=False, timeout=15)
        if response.status_code == 200:
            return True
        else:
            return False
    except Exception as e:
        print(f"[!] GetLoginData error: {e}")
        return False

def activate_account(uid, password):
    """Activate account using safe method (like acti.py)"""
    # Step 1: Guest token
    guest_url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    guest_headers = {
        "Host": "100067.connect.garena.com",
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G960F Build/PIE)",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "close"
    }
    guest_data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        "client_id": "100067"
    }
    try:
        resp = requests.post(guest_url, headers=guest_headers, data=guest_data, verify=False, timeout=15)
        if resp.status_code != 200:
            print(f"[!] Guest token failed for {uid}: {resp.status_code}")
            return False
        gjson = resp.json()
        access_token = gjson.get('access_token')
        open_id = gjson.get('open_id')
        if not access_token or not open_id:
            print(f"[!] No access_token or open_id for {uid}")
            return False
    except Exception as e:
        print(f"[!] Guest token error for {uid}: {e}")
        return False
    
    # Step 2: MajorLogin safe
    major_response = major_login_safe(access_token, open_id)
    if not major_response:
        print(f"[!] MajorLogin failed for {uid}")
        return False
    
    # Step 3: Parse response
    login_data = parse_safe_major_login_response(major_response)
    if not login_data:
        print(f"[!] Parse MajorLogin failed for {uid}")
        return False
    
    jwt_token = login_data['token']
    base_url = login_data['url']
    
    # Step 4: GetLoginData
    success = get_login_data_safe(jwt_token, access_token, base_url)
    if success:
        print(f"[+] Account {uid} activated successfully!")
    else:
        print(f"[!] GetLoginData failed for {uid}")
    return success

# =============================================================================
# AUTHENTICATION TOKEN BUILDER
# =============================================================================

def xAuThSTarTuP(account_uid, token, timestamp, key, iv):
    uid_hex = hex(account_uid)[2:]
    uid_len = len(uid_hex)
    encrypted_timestamp = DecodE_HeX(timestamp)
    encrypted_token = token.encode().hex()
    encrypted_packet = EnC_PacKeT(encrypted_token, key, iv)
    pkt_len = len(encrypted_packet) // 2
    pkt_len_hex = hex(pkt_len)[2:]
    if uid_len == 9:
        headers = '0000000'
    elif uid_len == 8:
        headers = '00000000'
    elif uid_len == 10:
        headers = '000000'
    else:
        headers = '0000000'
    return f"0115{headers}{uid_hex}{encrypted_timestamp}00000{pkt_len_hex}{encrypted_packet}"

# =============================================================================
# FF_CLIENT CLASS (UPDATED - uses WORKING_AVATARS)
# =============================================================================

class FF_Client:
    def __init__(self, uid, password):
        self.uid = uid
        self.password = password
        self.key = None
        self.iv = None
        self.auth_token = None
        self.online_sock = None
        self.region = None
        self.account_uid = None
        self.running = False
        self._need_reconnect = False
        self._connect()
        threading.Thread(target=self._spam_loop, daemon=True).start()

    def _full_auth(self):
        """Authenticate using safe activation method"""
        if not activate_account(self.uid, self.password):
            return False
        
        try:
            # Step 1: Get guest token
            guest_url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
            guest_headers = {
                "Host": "100067.connect.garena.com",
                "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; SM-G960F Build/PIE)",
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "close"
            }
            guest_data = {
                "uid": self.uid,
                "password": self.password,
                "response_type": "token",
                "client_type": "2",
                "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
                "client_id": "100067"
            }
            resp = requests.post(guest_url, headers=guest_headers, data=guest_data, verify=False, timeout=15)
            if resp.status_code != 200:
                return False
            gjson = resp.json()
            access_token = gjson.get('access_token')
            open_id = gjson.get('open_id')
            if not access_token or not open_id:
                return False
            
            # Step 2: MajorLogin
            major_response = major_login_safe(access_token, open_id)
            if not major_response:
                return False
            
            login_data = parse_safe_major_login_response(major_response)
            if not login_data:
                return False
            
            self.key = login_data['key']
            self.iv = login_data['iv']
            token = login_data['token']
            timestamp = login_data['timestamp']
            self.account_uid = login_data['account_uid']
            self.region = login_data['region']
            
            # Step 3: Get server IP
            payload = build_get_login_data_payload(token, access_token)
            if not payload:
                return False
            
            url = f"{login_data['url']}/GetLoginData"
            headers = {
                'Authorization': f'Bearer {token}',
                'X-Unity-Version': '2018.4.11f1',
                'X-GA': 'v1 1',
                'ReleaseVersion': 'OB54',
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
                'Connection': 'close',
                'Accept-Encoding': 'gzip, deflate, br',
            }
            
            response = requests.post(url, headers=headers, data=payload, verify=False, timeout=15)
            if response.status_code != 200:
                return False
            
            # Parse GetLoginData response
            try:
                res = PorTs_pb2.GetLoginData()
                res.ParseFromString(response.content)
                online_ip, online_port = res.Online_IP_Port.split(":")
                self.online_ip = online_ip
                self.online_port = int(online_port)
            except Exception as e:
                print(f"[!] Parse GetLoginData error: {e}")
                return False
            
            # Build auth token
            self.auth_token = xAuThSTarTuP(int(self.account_uid), token, int(timestamp), self.key, self.iv)
            return True
            
        except Exception as e:
            print(f"[!] Full auth error for {self.uid}: {e}")
            return False

    def _connect_online(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((self.online_ip, self.online_port))
        sock.send(bytes.fromhex(self.auth_token))
        resp = sock.recv(4096)
        if not resp:
            sock.close()
            return None
        print(f"[+] {self.uid} Online connected")
        return sock

    def _reader(self, sock):
        while self.running:
            try:
                data = sock.recv(4096)
                if not data:
                    break
            except Exception:
                break
        self.running = False
        self._need_reconnect = True

    def _connect(self):
        if not self._full_auth():
            print(f"[-] {self.uid} Auth failed (network/DNS error). Retrying later...")
            time.sleep(30)
            self._connect()
            return
        sock = self._connect_online()
        if not sock:
            return
        self.online_sock = sock
        self.running = True
        self._need_reconnect = False
        threading.Thread(target=self._reader, args=(sock,), daemon=True).start()
        with connected_clients_lock:
            connected_clients[self.uid] = self
            print(f"Account {self.uid} online. Total: {len(connected_clients)}")

    def reconnect(self):
        if self.online_sock:
            try:
                self.online_sock.close()
            except:
                pass
        self.running = False
        self._connect()

    def send_all_spams(self, target_id):
        if not self.online_sock or self._need_reconnect:
            self.reconnect()
            if not self.online_sock:
                return
        try:
            self.online_sock.send(openroom(self.key, self.iv))
            time.sleep(0.05)
            for i in range(10):
                self.online_sock.send(spmroom(self.key, self.iv, target_id))
                time.sleep(0.03)
            for i in range(5):
                room_spam = Room_Spam_Full(target_id, 12345678, f"JOIN FAST! {i+1}", self.key, self.iv)
                self.online_sock.send(room_spam)
                time.sleep(0.03)
            # ===== UPDATED: Using WORKING_AVATARS from xBunnEr =====
            for badge in ["s1", "s2", "s3", "s4", "s5"]:
                pkt = request_join_with_badge(target_id, BADGE_VALUES[badge], self.key, self.iv, self.region)
                if pkt:
                    self.online_sock.send(pkt)
                time.sleep(0.03)
            self.online_sock.send(OpEnSq(self.key, self.iv, self.region))
            time.sleep(0.05)
            c5 = cHSq(5, target_id, self.key, self.iv, self.region)
            self.online_sock.send(c5)
            inv5 = SEnd_InV(5, target_id, self.key, self.iv, self.region)
            self.online_sock.send(inv5)
            time.sleep(0.03)
            snd = SEnd_InV_Full(5, target_id, self.key, self.iv, self.region)
            self.online_sock.send(snd)
            time.sleep(0.03)
            for num in [3,4,5,6]:
                c = cHSq(num, target_id, self.key, self.iv, self.region)
                self.online_sock.send(c)
                inv = SEnd_InV(num, target_id, self.key, self.iv, self.region)
                self.online_sock.send(inv)
                time.sleep(0.03)
            self.online_sock.send(ExiT(self.key, self.iv))
        except Exception as e:
            print(f"[{self.uid}] Error spamming {target_id}: {e}")
            self._need_reconnect = True

    def _spam_loop(self):
        while self.running:
            try:
                with all_targets_lock:
                    targets = list(all_targets)
                if not targets:
                    time.sleep(0.5)
                    continue
                for target in targets:
                    self.send_all_spams(target)
            except Exception as e:
                print(f"[{self.uid}] Spam loop error: {e}")
                time.sleep(1)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def load_accounts():
    accounts = []
    try:
        with open("acc.txt", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and ":" in line and not line.startswith("#"):
                    uid, pwd = line.split(":", 1)
                    accounts.append((uid, pwd))
    except FileNotFoundError:
        print("acc.txt not found!")
    return accounts

def start_all_accounts():
    accounts = load_accounts()
    if not accounts:
        print("No accounts found in acc.txt")
        return
    for uid, pwd in accounts:
        threading.Thread(target=lambda: FF_Client(uid, pwd), daemon=True).start()
        time.sleep(3)

# =============================================================================
# STATUS MONITOR (with fixed squad detection)
# =============================================================================

_Hr = {
    'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
    'Connection': 'Keep-Alive',
    'Accept-Encoding': 'gzip',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Expect': '100-continue',
    'X-Unity-Version': '2018.4.11f1',
    'X-GA': 'v1 1',
    'ReleaseVersion': 'OB54',
}
_TTL = 6 * 60 * 60
_cx = {}
_lk = threading.Lock()

def _rdVr(data, pos):
    n = 0; sh = 0
    while True:
        b = data[pos]; pos += 1
        n |= (b & 0x7F) << sh; sh += 7
        if not b & 0x80: break
    return n, pos

def _pbF(data):
    out = {}; pos = 0
    while pos < len(data):
        try:
            tag, pos = _rdVr(data, pos)
            fn = tag >> 3; wt = tag & 0x7
            if wt == 0:
                v, pos = _rdVr(data, pos); out[fn] = v
            elif wt == 2:
                ln, pos = _rdVr(data, pos); out[fn] = data[pos:pos+ln]; pos += ln
            elif wt == 1:
                out[fn] = data[pos:pos+8]; pos += 8
            elif wt == 5:
                out[fn] = data[pos:pos+4]; pos += 4
            else: break
        except: break
    return out

async def _vr(n):
    h = []
    while True:
        b = n & 0x7F; n >>= 7
        if n: b |= 0x80
        h.append(b)
        if not n: break
    return bytes(h)

async def _enc(hx, k, v):
    return AES.new(k, AES.MODE_CBC, v).encrypt(pad(bytes.fromhex(hx), 16)).hex()

async def _hx(n):
    f = hex(n)[2:]
    return ('0' + f) if len(f) == 1 else f

async def _var(fn, val):
    return await _vr((fn << 3) | 0) + await _vr(val)

async def _len(fn, val):
    e = val.encode() if isinstance(val, str) else val
    return await _vr((fn << 3) | 2) + await _vr(len(e)) + e

async def _pb(flds):
    p = bytearray()
    for f, v in flds.items():
        if isinstance(v, dict): p.extend(await _len(f, await _pb(v)))
        elif isinstance(v, int): p.extend(await _var(f, v))
        elif isinstance(v, (str, bytes)): p.extend(await _len(f, v))
    return p

async def _pk(px, n, k, v):
    e = await _enc(px, k, v)
    _ = await _hx(len(e) // 2)
    m = {2:'000000', 3:'00000', 4:'0000', 5:'000'}
    return bytes.fromhex(n + m.get(len(_), '000000') + _ + e)

async def _fix(rs):
    d = {}
    for r in rs:
        fd = {'wire_type': r.wire_type}
        if r.wire_type in ('varint', 'string', 'bytes'): fd['data'] = r.data
        elif r.wire_type == 'length_delimited': fd['data'] = await _fix(r.data.results)
        d[r.field] = fd
    return d

async def _parse(hx):
    try:
        from protobuf_decoder.protobuf_decoder import Parser
        return json.dumps(await _fix(Parser().parse(hx)))
    except: return None

async def _uidEnc(uid):
    return (await _pb({1: int(uid)})).hex()[2:]

async def _stPkt(uid, k, v):
    ue = await _uidEnc(int(uid))
    return await _pk(f"080112090A05{ue}1005", '0F15', k, v)

async def _rmPkt(ruid, k, v):
    return await _pk((await _pb({1: 1, 2: {1: ruid, 3: {}, 4: 1, 6: 'en'}})).hex(), '0E15', k, v)

def _tdiff(ts):
    d = int((datetime.now() - datetime.fromtimestamp(ts)).total_seconds())
    return f"{(abs(d) % 3600) // 60:02}:{abs(d) % 60:02}"

def _pStatus(pkt):
    data = json.loads(pkt)
    if '5' not in data or 'data' not in data['5']: return {'status': 'OFFLINE'}
    jd = data['5']['data']
    if '1' not in jd or 'data' not in jd['1']: return {'status': 'OFFLINE'}
    d = jd['1']['data']
    if '3' not in d or 'data' not in d['3']: return {'status': 'OFFLINE'}
    st = d['3']['data']
    gc = d.get('9', {}).get('data', 0)
    cm = d.get('10', {}).get('data', 0) + 1 if '10' in d else 0
    go = d.get('8', {}).get('data', 0)
    tg = d.get('4', {}).get('data', 0)
    m5 = d.get('5', {}).get('data')
    m6 = d.get('6', {}).get('data')
    mn = sc = 0
    if tg:
        a, b = _tdiff(tg).split(':'); mn = int(a); sc = int(b)
    if st == 4:
        return {'status': 'IN_ROOM', 'room_uid': d.get('15', {}).get('data'),
                'players': f"{d.get('17',{}).get('data',0)}/{d.get('18',{}).get('data',0)}",
                'room_owner': d.get('1', {}).get('data')}
    base = {1:'SOLO', 2:'INSQUAD', 3:'INGAME', 5:'INGAME', 7:'MATCHMAKING', 6:'SOCIAL_ISLAND'}.get(st, 'OFFLINE')
    mode = None
    f14 = d.get('14', {}).get('data')
    if f14 == 1: mode = 'TRAINING'
    elif f14 == 2: mode = 'SOCIAL_ISLAND'
    mm = {(2,1):'BR_RANK',(5,23):'TRAINING',(6,15):'CS_RANK',(1,43):'LONE_WOLF',
          (1,1):'BERMUDA',(1,15):'CLASH_SQUAD',(1,29):'CONVOY_CRUNCH',(1,61):'FREE_FOR_ALL'}
    if (m5, m6) in mm: mode = mm[(m5, m6)]
    res = {'status': base, 'mode': mode}
    if base == 'INSQUAD':
        res['squad_owner'] = go
        res['squad_size'] = f"{gc}/{cm}" if gc else None
    if base in ('INGAME', 'INSQUAD') and tg:
        res['time_playing'] = f"{mn}m {sc}s"
    return res

def _pRoom(pkt):
    data = json.loads(pkt)
    rd = data['5']['data']['1']['data']
    mm = {1:'BERMUDA',201:'BATTLE_CAGE',15:'CLASH_SQUAD',43:'LONE_WOLF',3:'RUSH_HOUR',27:'BOMB_SQUAD_5V5',24:'DEATH_MATCH'}
    return {
        'room_id': int(rd['1']['data']),
        'room_name': rd['2']['data'],
        'owner_uid': int(rd['37']['data']['1']['data']),
        'mode': mm.get(rd.get('4', {}).get('data'), 'UNKNOWN'),
        'players': f"{rd.get('6',{}).get('data',0)}/{rd.get('7',{}).get('data',0)}",
        'spectators': rd.get('9', {}).get('data', 0),
        'emulator': bool(rd.get('17', {}).get('data', 1)),
    }

async def _rAll(reader, timeout=5):
    buf = b''
    while True:
        try: chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
        except asyncio.TimeoutError: break
        if not chunk: break
        buf += chunk
    return buf

async def _scan(buf, k, v):
    h = buf.hex()
    for mk, pt in [('0f00','0f'),('0e00','0e')]:
        i = h.find(mk)
        if i != -1 and i % 2 == 0: return pt, h[i + 10:]
    if len(buf) > 5:
        pl = buf[5:]; pl = pl[:len(pl) - (len(pl) % 16)]
        if len(pl) >= 16:
            try:
                dc = unpad(AES.new(k, AES.MODE_CBC, v).decrypt(pl), 16).hex()
                for mk, pt in [('0f00','0f'),('0e00','0e')]:
                    i = dc.find(mk)
                    if i != -1 and i % 2 == 0: return pt, dc[i + 10:]
            except: pass
    return None, None

async def _mkLogin(oid, atk):
    return await _pb({
        3: str(datetime.now())[:-7], 4: 'free fire', 5: 1, 7: '1.126.1',
        8: 'Android OS 9 / API-28 (PQ3B.190801.10101846/G9650ZHU2ARC6)',
        9: 'Handheld', 10: 'Verizon', 11: 'WIFI', 12: 1920, 13: 1080,
        14: '280', 15: 'ARM64 FP ASIMD AES VMH | 2865 | 4', 16: 3003,
        17: 'Adreno (TM) 640', 18: 'OpenGL ES 3.1 v1.46',
        19: 'Google|34a7dcdf-a7d5-4cb6-8d7e-3b0e448a0c57',
        20: '223.191.51.89', 21: 'en', 22: oid, 23: '4', 24: 'Handheld',
        25: {6: 55, 8: 81},
        29: atk, 30: 1, 73: 3, 78: 3, 79: 2, 81: '64',
        93: 'android', 97: 1, 98: 1, 99: '4', 100: '4',
    })

async def _auth(uid, tok, ts, k, v):
    uh = hex(uid)[2:]
    hd = {9:'0000000',8:'00000000',10:'000000',7:'000000000'}.get(len(uh),'0000000')
    e = await _enc(tok.encode().hex(), k, v)
    el = await _hx(len(e) // 2)
    return f"0115{hd}{uh}{await _hx(ts)}00000{el}{e}"

async def _login(status_uid, status_pw, retry=3):
    sx = ssl.create_default_context()
    sx.check_hostname = False; sx.verify_mode = ssl.CERT_NONE

    for attempt in range(retry):
        try:
            async with aiohttp.ClientSession() as s:
                async with s.post('https://100067.connect.garena.com/oauth/guest/token/grant', headers=_Hr,
                    data={'uid':status_uid,'password':status_pw,'response_type':'token','client_type':'2',
                          'client_secret':'2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3',
                          'client_id':'100067'}, ssl=sx) as r:
                    if r.status != 200: raise Exception(f"OAuth {r.status}")
                    d = await r.json()
                    oid = d['open_id']; atk = d['access_token']

            raw = await _mkLogin(oid, atk)
            ep  = AES.new(Config.AES_KEY, AES.MODE_CBC, Config.AES_IV).encrypt(pad(raw, 16))

            async with aiohttp.ClientSession() as s:
                async with s.post(Config.MAJOR_LOGIN_URL + '/MajorLogin', data=ep, headers=_Hr, ssl=sx) as r:
                    if r.status != 200: raise Exception(f"MajorLogin {r.status}")
                    mr = await r.read()

            mlr = _pbF(mr)
            tok = mlr[8].decode()
            tgt = mlr[1]
            k   = mlr[22]
            v   = mlr[23]
            ts  = mlr[21]
            url = mlr[10].decode()

            h2 = {**_Hr, 'Authorization': f'Bearer {tok}'}
            async with aiohttp.ClientSession() as s:
                async with s.post(f"{url}/GetLoginData", data=ep, headers=h2, ssl=sx) as r:
                    if r.status != 200: raise Exception(f"GetLoginData {r.status}")
                    lr = await r.read()

            ld = _pbF(lr)
            ip, port = ld[14].decode().split(':')
            at = await _auth(int(tgt), tok, int(ts), k, v)
            print(f"[Monitor] Logged in with {status_uid} -> account_id {tgt}")
            return {'account_id':tgt,'token':tok,'key':k,'iv':v,'ip':ip,'port':int(port),'auth':at,'exp':time.time()+_TTL}
        except Exception as e:
            print(f"[Monitor] Login attempt {attempt+1}/{retry} failed: {e}")
            if attempt < retry - 1:
                await asyncio.sleep(10)
    return None

def _sess(status_uid, status_pw):
    with _lk:
        s = _cx.get('s')
        if s and time.time() < s['exp']: return s
    ns = asyncio.run(_login(status_uid, status_pw))
    if ns is None:
        raise Exception("Failed to login after retries")
    with _lk: _cx['s'] = ns
    return ns

async def _query(uid, sx):
    rd, wr = await asyncio.open_connection(sx['ip'], sx['port'])
    try:
        wr.write(bytes.fromhex(sx['auth'])); await wr.drain()
        await _rAll(rd, timeout=3)
        pkt = await _stPkt(uid, sx['key'], sx['iv'])
        wr.write(pkt); await wr.drain()
        buf = await _rAll(rd, timeout=5)
        if not buf: return {'status': 'NO_RESPONSE'}
        pt, pl = await _scan(buf, sx['key'], sx['iv'])
        if pt == '0f':
            raw = await _parse(pl)
            if not raw: return {'status': 'PARSE_ERROR'}
            info = _pStatus(raw)
            if info.get('status') == 'IN_ROOM':
                wr.write(await _rmPkt(int(info['room_uid']), sx['key'], sx['iv'])); await wr.drain()
                rb = await _rAll(rd, timeout=5)
                if rb:
                    rt, rp = await _scan(rb, sx['key'], sx['iv'])
                    if rt == '0e':
                        rr = await _parse(rp)
                        if rr: info['room_info'] = _pRoom(rr)
            return info
        elif pt == '0e':
            raw = await _parse(pl)
            return _pRoom(raw) if raw else {'status': 'PARSE_ERROR'}
        return {'status': 'UNKNOWN', 'buf': buf.hex()[:120]}
    finally:
        wr.close()
        try: await wr.wait_closed()
        except: pass

# =============================================================================
# USER STARTED TARGETS
# =============================================================================

user_started_targets = set()
user_started_lock = threading.Lock()

def load_user_started():
    with user_started_lock:
        user_started_targets.clear()
        if os.path.exists("target.txt"):
            with open("target.txt", "r") as f:
                for line in f:
                    uid = line.strip()
                    if uid and uid.isdigit():
                        user_started_targets.add(uid)

load_user_started()

# =============================================================================
# STATUS MONITOR LOOP
# =============================================================================

def status_monitor_loop_fixed(status_uid, status_pw):
    time.sleep(10)
    while spam_running:
        try:
            with user_started_lock:
                targets_to_check = list(user_started_targets)
            if not targets_to_check:
                time.sleep(5)
                continue
            try:
                sx = _sess(status_uid, status_pw)
            except Exception as e:
                print(f"[Monitor] Cannot get session: {e}. Retrying in 30s...")
                time.sleep(30)
                continue
            for orig_uid in targets_to_check:
                try:
                    status = asyncio.run(_query(orig_uid, sx))
                    if status and status.get('status') == 'INSQUAD' and status.get('squad_owner'):
                        owner = str(status['squad_owner'])
                        if owner != orig_uid:
                            with all_targets_lock:
                                if owner not in all_targets:
                                    all_targets.add(owner)
                                    print(f"[Monitor] Auto‑added squad owner {owner} (from target {orig_uid})")
                            with open("leader.txt", "r+") as f:
                                existing = [line.strip() for line in f]
                                if owner not in existing:
                                    f.write(f"{owner}\n")
                except Exception as e:
                    print(f"[Monitor] Error checking {orig_uid}: {e}")
            time.sleep(5)
        except Exception as e:
            print(f"[Monitor] Loop error: {e}")
            time.sleep(5)

# =============================================================================
# FLASK WEB SERVER
# =============================================================================

app = Flask(__name__)

HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="hi">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔥 MAFU FF Ultimate 24/7 Spam Tool</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            background: linear-gradient(135deg, #0a0a14 0%, #12121f 100%);
            font-family: 'Segoe UI', system-ui, sans-serif;
            color: #f0e6ff;
            padding: 20px;
            min-height: 100vh;
        }
        .container { max-width: 1100px; margin: 0 auto; }
        .card {
            background: rgba(255,255,255,0.05);
            backdrop-filter: blur(12px);
            border-radius: 24px;
            padding: 28px;
            margin-bottom: 22px;
            border: 1px solid rgba(255,255,255,0.1);
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
        }
        h1 {
            font-size: 2.5rem;
            text-align: center;
            background: linear-gradient(135deg, #ff3c7e, #ff5e3a);
            -webkit-background-clip: text;
            background-clip: text;
            color: transparent;
            margin-bottom: 10px;
        }
        .credit { text-align: center; opacity: 0.7; margin-bottom: 30px; }
        h2 { margin-bottom: 20px; font-size: 1.3rem; border-left: 4px solid #ff3c7e; padding-left: 16px; }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: rgba(0,0,0,0.3);
            border-radius: 16px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(255,255,255,0.08);
        }
        .stat-number { font-size: 2.5rem; font-weight: bold; color: #ff5e8a; }
        .account-list {
            max-height: 180px;
            overflow-y: auto;
            background: rgba(0,0,0,0.2);
            border-radius: 12px;
            padding: 12px;
            font-family: monospace;
            font-size: 0.85rem;
        }
        .account-item {
            padding: 6px 10px;
            border-bottom: 1px solid rgba(255,255,255,0.05);
        }
        .target-badge {
            display: inline-block;
            background: linear-gradient(135deg, #ff3c7e, #b347ea);
            padding: 6px 14px;
            border-radius: 20px;
            margin: 5px;
            font-size: 0.8rem;
            font-weight: bold;
        }
        .form-group {
            display: flex;
            gap: 15px;
            flex-wrap: wrap;
        }
        .input-field { flex: 1; min-width: 180px; }
        label { display: block; margin-bottom: 6px; font-size: 0.8rem; opacity: 0.8; }
        input {
            width: 100%;
            padding: 12px 16px;
            background: rgba(0,0,0,0.3);
            border: 1px solid rgba(255,255,255,0.15);
            border-radius: 12px;
            color: white;
            font-size: 0.95rem;
        }
        input:focus { outline: none; border-color: #ff3c7e; }
        button {
            padding: 12px 28px;
            background: linear-gradient(135deg, #ff3c7e, #ff5e3a);
            border: none;
            border-radius: 12px;
            color: white;
            font-weight: bold;
            cursor: pointer;
            transition: 0.3s;
        }
        button:hover { transform: translateY(-2px); box-shadow: 0 6px 20px rgba(255,60,126,0.4); }
        .stop-btn { background: linear-gradient(135deg, #3d3d5c, #1e1e38); }
        .message {
            margin-top: 15px;
            padding: 10px;
            border-radius: 10px;
            display: none;
        }
        .message.success { background: rgba(0,255,100,0.1); border: 1px solid #0f0; display: block; }
        .message.error { background: rgba(255,0,0,0.1); border: 1px solid #f00; display: block; }
        footer { text-align: center; margin-top: 30px; opacity: 0.5; font-size: 0.8rem; }
        @media (max-width: 768px) {
            .form-group { flex-direction: column; }
            button { width: 100%; }
            h1 { font-size: 1.8rem; }
        }
    </style>
</head>
<body>
<div class="container">
    <h1>🔥 MAFU FF Ultimate 24/7 Spam Tool 🔥</h1>
    <div class="credit">⚡ Credit: MAFU FF | Auto Squad Owner Detection | 24/7 All Targets ⚡</div>

    <div class="card">
        <h2>📊 Status</h2>
        <div class="status-grid">
            <div class="stat-card">
                <div class="stat-number" id="accCount">0</div>
                <div>Bot Online</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="targetCount">0</div>
                <div>Active Targets</div>
            </div>
        </div>
        <strong>📋 Connected Bots:</strong>
        <div class="account-list" id="accountList">Loading...</div>
        <div class="active-targets" style="margin-top: 15px;">
            <strong>🎯 Active Targets (from target.txt + leader.txt):</strong>
            <div id="activeTargets"></div>
        </div>
    </div>

    <div class="card">
        <h2>🚀 Add Target (24/7)</h2>
        <div class="form-group">
            <div class="input-field">
                <label>UID to add</label>
                <input type="text" id="addUid" placeholder="Example: 15442063519">
            </div>
            <button id="addBtn">▶ Add to target.txt</button>
        </div>
        <div id="addMessage" class="message"></div>
    </div>

    <div class="card">
        <h2>🛑 Remove Target</h2>
        <div class="form-group">
            <div class="input-field">
                <label>UID to remove</label>
                <input type="text" id="removeUid" placeholder="Enter UID">
            </div>
            <button id="removeBtn" class="stop-btn">⏹ Remove from spam</button>
        </div>
        <div id="removeMessage" class="message"></div>
    </div>

    <footer>⚡ Every bot spams ALL targets (from target.txt + leader.txt) simultaneously, 24/7.<br>Squad owners are auto‑added to leader.txt and spammed immediately. Made By MAFU FF ⚡</footer>
</div>

<script>
function fetchStatus() {
    fetch('/api/status')
        .then(res => res.json())
        .then(data => {
            document.getElementById('accCount').innerText = data.connected_accounts;
            document.getElementById('targetCount').innerText = data.all_targets.length;
            const accList = document.getElementById('accountList');
            if (data.accounts.length) {
                accList.innerHTML = data.accounts.map(acc => `<div class="account-item">📱 ${acc}</div>`).join('');
            } else {
                accList.innerHTML = '<div class="account-item">No bots online</div>';
            }
            const targetsDiv = document.getElementById('activeTargets');
            if (data.all_targets && data.all_targets.length) {
                targetsDiv.innerHTML = data.all_targets.map(t => `<span class="target-badge">${t}</span>`).join('');
            } else {
                targetsDiv.innerHTML = '<span style="opacity:0.7;">No active spam</span>';
            }
        })
        .catch(err => console.error(err));
}

function showMessage(elId, text, isError = false) {
    const el = document.getElementById(elId);
    el.innerText = text;
    el.className = 'message ' + (isError ? 'error' : 'success');
    el.style.display = 'block';
    setTimeout(() => el.style.display = 'none', 5000);
}

document.getElementById('addBtn').onclick = () => {
    const uid = document.getElementById('addUid').value.trim();
    if (!uid) { showMessage('addMessage', 'Please enter UID', true); return; }
    fetch(`/add?uid=${encodeURIComponent(uid)}`)
        .then(res => res.json())
        .then(data => {
            if (data.error) showMessage('addMessage', data.error, true);
            else {
                showMessage('addMessage', `✅ ${data.status}`);
                document.getElementById('addUid').value = '';
                fetchStatus();
            }
        })
        .catch(() => showMessage('addMessage', 'Server error', true));
};

document.getElementById('removeBtn').onclick = () => {
    const uid = document.getElementById('removeUid').value.trim();
    if (!uid) { showMessage('removeMessage', 'Please enter UID', true); return; }
    fetch(`/remove?uid=${encodeURIComponent(uid)}`)
        .then(res => res.json())
        .then(data => {
            if (data.error) showMessage('removeMessage', data.error, true);
            else {
                showMessage('removeMessage', `🛑 ${data.status}`);
                document.getElementById('removeUid').value = '';
                fetchStatus();
            }
        })
        .catch(() => showMessage('removeMessage', 'Server error', true));
};

fetchStatus();
setInterval(fetchStatus, 3000);
</script>
</body>
</html>'''

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/status')
def api_status():
    with connected_clients_lock:
        acc_list = list(connected_clients.keys())
    with all_targets_lock:
        targets = list(all_targets)
    return jsonify({
        'connected_accounts': len(connected_clients),
        'accounts': acc_list,
        'all_targets': targets
    })

@app.route('/add')
def add_route():
    uid = request.args.get('uid')
    if not uid or not uid.isdigit():
        return jsonify({'error': 'Invalid UID'}), 400
    if not connected_clients:
        return jsonify({'error': 'No bots online'}), 500
    if add_target_to_file(uid):
        with user_started_lock:
            user_started_targets.add(uid)
        return jsonify({'status': f'Added {uid} to target.txt and spam list'})
    else:
        return jsonify({'error': 'Could not add UID'}), 500

@app.route('/remove')
def remove_route():
    uid = request.args.get('uid')
    if not uid or not uid.isdigit():
        return jsonify({'error': 'Invalid UID'}), 400
    if remove_target_from_file(uid):
        with user_started_lock:
            user_started_targets.discard(uid)
        return jsonify({'status': f'Removed {uid} from spam list and target.txt'})
    else:
        return jsonify({'error': f'UID {uid} not found in targets'}), 404

def add_target_to_file(uid):
    if not uid or not uid.isdigit():
        return False
    with open("target.txt", "r+") as f:
        existing = [line.strip() for line in f]
        if uid not in existing:
            f.write(f"{uid}\n")
    with all_targets_lock:
        all_targets.add(uid)
    return True

def remove_target_from_file(uid):
    if not uid or not uid.isdigit():
        return False
    if os.path.exists("target.txt"):
        with open("target.txt", "r") as f:
            lines = f.readlines()
        with open("target.txt", "w") as f:
            for line in lines:
                if line.strip() != uid:
                    f.write(line)
    with all_targets_lock:
        all_targets.discard(uid)
    return True

# =============================================================================
# MAIN
# =============================================================================

if __name__ == '__main__':
    threading.Thread(target=start_all_accounts, daemon=True).start()
    time.sleep(10)
    accounts = load_accounts()
    if accounts:
        status_uid, status_pw = accounts[0]
        print(f"[Monitor] Using status account: {status_uid}")
        threading.Thread(target=status_monitor_loop_fixed, args=(status_uid, status_pw), daemon=True).start()
    else:
        print("[Monitor] No accounts in acc.txt, status monitor disabled")
    app.run(host='0.0.0.0', port=5080, debug=False, use_reloader=False)