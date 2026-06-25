#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║          CryptoForge v2.0 — Ferramenta de Criptografia           ║
║          by kaltel | Python 3.8+                                  ║
╚══════════════════════════════════════════════════════════════════╝

Suporta:
  • Cifra Proprietária (formato: HASH+PAYLOAD|KEY=HASH||...|*|SALT)
  • AES-256-CBC / AES-256-GCM
  • ChaCha20-Poly1305
  • RSA-2048 / RSA-4096
  • Fernet (AES-128-CBC + HMAC-SHA256)
  • Base64 / Base85 / Base32
  • XOR (chave simples ou derivada)
  • ROT13 / César (offset customizável)
  • Vigenère
  • Vernam (One-Time Pad)
  • HMAC-SHA256 / HMAC-SHA512
  • PBKDF2 / Argon2id / scrypt (KDF)
  • Hash: MD5, SHA1, SHA256, SHA512, BLAKE2b, BLAKE2s
  • Hashing de arquivos
  • Modo interativo (menu)
  • CLI completo (argparse)
"""

import os
import sys
import json
import time
import base64
import hashlib
import hmac
import struct
import secrets
import argparse
import getpass
import binascii
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Union

# ─────────────────────────── CORES ────────────────────────────────
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    MAGENTA= "\033[95m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BG_BLK = "\033[40m"

def ok(msg):  print(f"{C.GREEN}  ✓ {msg}{C.RESET}")
def err(msg): print(f"{C.RED}  ✗ {msg}{C.RESET}")
def inf(msg): print(f"{C.CYAN}  ℹ {msg}{C.RESET}")
def warn(msg):print(f"{C.YELLOW}  ⚠ {msg}{C.RESET}")
def sec(msg): print(f"{C.MAGENTA}  🔐 {msg}{C.RESET}")

BANNER = f"""{C.CYAN}{C.BOLD}
  ██████╗██████╗ ██╗   ██╗██████╗ ████████╗ ██████╗
 ██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝██╔═══██╗
 ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   ██║   ██║
 ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   ██║   ██║
 ╚██████╗██║  ██║   ██║   ██║        ██║   ╚██████╔╝
  ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝    ╚═════╝
         {C.MAGENTA}F O R G E{C.CYAN}  v2.0  —  Ferramenta de Criptografia{C.RESET}
{C.DIM}  Python · AES · RSA · ChaCha20 · Fernet · XOR · Vigenère · OTP{C.RESET}
"""

# ──────────────────────── VERIFICAÇÃO DE DEPS ──────────────────────
def check_deps():
    missing = []
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.fernet import Fernet
    except ImportError:
        missing.append("cryptography")
    try:
        import argon2
    except ImportError:
        missing.append("argon2-cffi")
    return missing

# ──────────────────────── UTILITÁRIOS ──────────────────────────────
def gen_salt(size=16) -> bytes:
    return secrets.token_bytes(size)

def bytes_to_hex(b: bytes) -> str:
    return binascii.hexlify(b).decode()

def hex_to_bytes(h: str) -> bytes:
    return binascii.unhexlify(h)

def derive_key_pbkdf2(password: str, salt: bytes, length=32, iterations=600_000) -> bytes:
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=length)

def derive_key_scrypt(password: str, salt: bytes, length=32) -> bytes:
    return hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=length)

def derive_key_argon2(password: str, salt: bytes, length=32) -> bytes:
    try:
        from argon2.low_level import hash_secret_raw, Type
        return hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=length,
            type=Type.ID,
        )
    except ImportError:
        warn("argon2-cffi não instalado. Usando scrypt como fallback.")
        return derive_key_scrypt(password, salt, length)

# ══════════════════════════════════════════════════════════════════
# 1. CIFRA PROPRIETÁRIA
# ══════════════════════════════════════════════════════════════════
class ProprietaryCipher:
    """Formato: HASH16+PAYLOAD|KEY=HASH||...|*|SALT"""

    @staticmethod
    def _make_hash(data: str) -> str:
        return hashlib.md5(data.encode()).hexdigest()[:16]

    @staticmethod
    def _xor_encode(data: str, key: str) -> str:
        out = []
        for i, ch in enumerate(data):
            out.append(chr(ord(ch) ^ ord(key[i % len(key)])))
        return ''.join(out)

    @classmethod
    def encrypt(cls, plaintext: str, keys: list = None, salt: str = None) -> str:
        if not keys:
            keys = [secrets.token_hex(2).upper()[:2] for _ in range(max(1, len(plaintext)//8 + 1))]
        if not salt:
            salt = str(secrets.randbelow(9999)).zfill(4)

        chunk_size = max(4, len(plaintext) // len(keys) + 1)
        chunks = [plaintext[i:i+chunk_size] for i in range(0, len(plaintext), chunk_size)]

        blocks = []
        for idx, chunk in enumerate(chunks):
            key = keys[idx % len(keys)]
            encoded = cls._xor_encode(chunk, key)
            h = cls._make_hash(chunk + key + salt)
            block = f"{h}{encoded}|{key}={h}"
            blocks.append(block)

        return '||'.join(blocks) + f"|*|{salt}"

    @classmethod
    def decrypt(cls, ciphertext: str) -> str:
        if '|*|' not in ciphertext:
            raise ValueError("Formato inválido: salt ausente")
        main, salt = ciphertext.rsplit('|*|', 1)
        blocks = main.split('||')
        parts = []
        for i, block in enumerate(blocks):
            if '=' not in block or '|' not in block:
                raise ValueError(f"Bloco {i+1} malformado")
            eq_idx = block.rindex('=')
            left = block[:eq_idx]
            stored_hash = block[eq_idx+1:]
            pipe_idx = left.rindex('|')
            encoded_with_prefix = left[:pipe_idx]
            key = left[pipe_idx+1:]
            hash_prefix = encoded_with_prefix[:16]
            encoded = encoded_with_prefix[16:]
            decoded = cls._xor_encode(encoded, key)
            verify = cls._make_hash(decoded + key + salt)
            if verify != hash_prefix:
                warn(f"Bloco {i+1}: hash não confere — dados podem estar corrompidos")
            parts.append(decoded)
        return ''.join(parts)

# ══════════════════════════════════════════════════════════════════
# 2. AES
# ══════════════════════════════════════════════════════════════════
class AESCipher:
    @staticmethod
    def encrypt_cbc(data: bytes, password: str) -> dict:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.backends import default_backend
        salt = gen_salt(16)
        iv   = gen_salt(16)
        key  = derive_key_pbkdf2(password, salt, 32)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(padded) + enc.finalize()
        return {
            "mode": "AES-256-CBC",
            "ciphertext": base64.b64encode(ct).decode(),
            "iv": bytes_to_hex(iv),
            "salt": bytes_to_hex(salt),
            "kdf": "PBKDF2-SHA256-600k"
        }

    @staticmethod
    def decrypt_cbc(data: dict, password: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.primitives import padding
        from cryptography.hazmat.backends import default_backend
        salt = hex_to_bytes(data["salt"])
        iv   = hex_to_bytes(data["iv"])
        key  = derive_key_pbkdf2(password, salt, 32)
        ct   = base64.b64decode(data["ciphertext"])
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ct) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(padded) + unpadder.finalize()

    @staticmethod
    def encrypt_gcm(data: bytes, password: str) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt  = gen_salt(16)
        nonce = gen_salt(12)
        key   = derive_key_scrypt(password, salt, 32)
        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(nonce, data, None)
        return {
            "mode": "AES-256-GCM",
            "ciphertext": base64.b64encode(ct).decode(),
            "nonce": bytes_to_hex(nonce),
            "salt": bytes_to_hex(salt),
            "kdf": "scrypt"
        }

    @staticmethod
    def decrypt_gcm(data: dict, password: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt  = hex_to_bytes(data["salt"])
        nonce = hex_to_bytes(data["nonce"])
        key   = derive_key_scrypt(password, salt, 32)
        ct    = base64.b64decode(data["ciphertext"])
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, None)

# ══════════════════════════════════════════════════════════════════
# 3. CHACHA20-POLY1305
# ══════════════════════════════════════════════════════════════════
class ChaCha20Cipher:
    @staticmethod
    def encrypt(data: bytes, password: str) -> dict:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        salt  = gen_salt(16)
        nonce = gen_salt(12)
        key   = derive_key_argon2(password, salt, 32)
        cc    = ChaCha20Poly1305(key)
        ct    = cc.encrypt(nonce, data, None)
        return {
            "mode": "ChaCha20-Poly1305",
            "ciphertext": base64.b64encode(ct).decode(),
            "nonce": bytes_to_hex(nonce),
            "salt": bytes_to_hex(salt),
            "kdf": "Argon2id"
        }

    @staticmethod
    def decrypt(data: dict, password: str) -> bytes:
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        salt  = hex_to_bytes(data["salt"])
        nonce = hex_to_bytes(data["nonce"])
        key   = derive_key_argon2(password, salt, 32)
        ct    = base64.b64decode(data["ciphertext"])
        cc    = ChaCha20Poly1305(key)
        return cc.decrypt(nonce, ct, None)

# ══════════════════════════════════════════════════════════════════
# 4. FERNET
# ══════════════════════════════════════════════════════════════════
class FernetCipher:
    @staticmethod
    def encrypt(data: bytes, password: str) -> dict:
        from cryptography.fernet import Fernet
        salt = gen_salt(16)
        key  = base64.urlsafe_b64encode(derive_key_pbkdf2(password, salt, 32))
        f    = Fernet(key)
        token = f.encrypt(data)
        return {
            "mode": "Fernet",
            "token": token.decode(),
            "salt": bytes_to_hex(salt),
            "kdf": "PBKDF2-SHA256-600k"
        }

    @staticmethod
    def decrypt(data: dict, password: str) -> bytes:
        from cryptography.fernet import Fernet
        salt  = hex_to_bytes(data["salt"])
        key   = base64.urlsafe_b64encode(derive_key_pbkdf2(password, salt, 32))
        f     = Fernet(key)
        return f.decrypt(data["token"].encode())

# ══════════════════════════════════════════════════════════════════
# 5. RSA
# ══════════════════════════════════════════════════════════════════
class RSACipher:
    @staticmethod
    def generate_keypair(bits=2048) -> Tuple[str, str]:
        from cryptography.hazmat.primitives.asymmetric import rsa, padding as apad
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.backends import default_backend
        priv = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=default_backend())
        pub  = priv.public_key()
        priv_pem = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ).decode()
        pub_pem = pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return priv_pem, pub_pem

    @staticmethod
    def encrypt(data: bytes, pub_pem: str) -> str:
        from cryptography.hazmat.primitives.asymmetric import padding as apad
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.backends import default_backend
        pub = serialization.load_pem_public_key(pub_pem.encode(), backend=default_backend())
        ct  = pub.encrypt(data, apad.OAEP(
            mgf=apad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))
        return base64.b64encode(ct).decode()

    @staticmethod
    def decrypt(ciphertext_b64: str, priv_pem: str) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import padding as apad
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.backends import default_backend
        priv = serialization.load_pem_private_key(priv_pem.encode(), password=None, backend=default_backend())
        ct   = base64.b64decode(ciphertext_b64)
        return priv.decrypt(ct, apad.OAEP(
            mgf=apad.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

# ══════════════════════════════════════════════════════════════════
# 6. CLÁSSICOS
# ══════════════════════════════════════════════════════════════════
class ClassicCiphers:
    @staticmethod
    def caesar_enc(text: str, shift: int) -> str:
        out = []
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                out.append(chr((ord(c) - base + shift) % 26 + base))
            else:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def caesar_dec(text: str, shift: int) -> str:
        return ClassicCiphers.caesar_enc(text, -shift)

    @staticmethod
    def rot13(text: str) -> str:
        return ClassicCiphers.caesar_enc(text, 13)

    @staticmethod
    def vigenere_enc(text: str, key: str) -> str:
        key = key.upper()
        out, ki = [], 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[ki % len(key)]) - ord('A')
                out.append(chr((ord(c) - base + shift) % 26 + base))
                ki += 1
            else:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def vigenere_dec(text: str, key: str) -> str:
        key = key.upper()
        out, ki = [], 0
        for c in text:
            if c.isalpha():
                base = ord('A') if c.isupper() else ord('a')
                shift = ord(key[ki % len(key)]) - ord('A')
                out.append(chr((ord(c) - base - shift) % 26 + base))
                ki += 1
            else:
                out.append(c)
        return ''.join(out)

    @staticmethod
    def xor_enc(data: bytes, key: bytes) -> bytes:
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    @staticmethod
    def vernam_enc(data: bytes) -> Tuple[bytes, bytes]:
        pad = secrets.token_bytes(len(data))
        ct  = bytes(a ^ b for a, b in zip(data, pad))
        return ct, pad

    @staticmethod
    def vernam_dec(ct: bytes, pad: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(ct, pad))

# ══════════════════════════════════════════════════════════════════
# 7. ENCODING
# ══════════════════════════════════════════════════════════════════
class Encoding:
    @staticmethod
    def b64_enc(data: bytes) -> str: return base64.b64encode(data).decode()
    @staticmethod
    def b64_dec(s: str) -> bytes:   return base64.b64decode(s)
    @staticmethod
    def b85_enc(data: bytes) -> str: return base64.b85encode(data).decode()
    @staticmethod
    def b85_dec(s: str) -> bytes:   return base64.b85decode(s)
    @staticmethod
    def b32_enc(data: bytes) -> str: return base64.b32encode(data).decode()
    @staticmethod
    def b32_dec(s: str) -> bytes:   return base64.b32decode(s)
    @staticmethod
    def hex_enc(data: bytes) -> str: return data.hex()
    @staticmethod
    def hex_dec(s: str) -> bytes:   return bytes.fromhex(s)

# ══════════════════════════════════════════════════════════════════
# 8. HASHING
# ══════════════════════════════════════════════════════════════════
class Hasher:
    ALGOS = ['md5','sha1','sha256','sha512','sha3_256','sha3_512','blake2b','blake2s']

    @staticmethod
    def hash_text(text: str, algo: str = 'sha256') -> str:
        h = hashlib.new(algo)
        h.update(text.encode('utf-8'))
        return h.hexdigest()

    @staticmethod
    def hash_file(path: str, algo: str = 'sha256') -> str:
        h = hashlib.new(algo)
        with open(path, 'rb') as f:
            for chunk in iter(lambda: f.read(65536), b''):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def hmac_sign(data: bytes, key: str, algo: str = 'sha256') -> str:
        h = hmac.new(key.encode(), data, getattr(hashlib, algo))
        return h.hexdigest()

    @staticmethod
    def hmac_verify(data: bytes, key: str, sig: str, algo: str = 'sha256') -> bool:
        expected = Hasher.hmac_sign(data, key, algo)
        return hmac.compare_digest(expected, sig)

# ══════════════════════════════════════════════════════════════════
# 9. ANÁLISE DE FORÇA
# ══════════════════════════════════════════════════════════════════
def password_strength(pwd: str) -> dict:
    score = 0
    tips = []
    if len(pwd) >= 8:  score += 1
    else: tips.append("Use ao menos 8 caracteres")
    if len(pwd) >= 16: score += 1
    else: tips.append("16+ caracteres é ideal")
    if any(c.isupper() for c in pwd): score += 1
    else: tips.append("Adicione letras maiúsculas")
    if any(c.islower() for c in pwd): score += 1
    else: tips.append("Adicione letras minúsculas")
    if any(c.isdigit() for c in pwd): score += 1
    else: tips.append("Adicione números")
    if any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in pwd): score += 1
    else: tips.append("Adicione símbolos especiais")
    h = len(set(pwd)) / len(pwd) if pwd else 0
    entropy = len(pwd) * (h * 6.5 + 1)
    labels = ["Muito fraca","Fraca","Razoável","Boa","Forte","Muito forte"]
    colors = [C.RED, C.RED, C.YELLOW, C.YELLOW, C.GREEN, C.GREEN]
    return {
        "score": score, "max": 6,
        "label": labels[min(score, 5)],
        "color": colors[min(score, 5)],
        "entropy_bits": round(entropy, 1),
        "tips": tips
    }

# ══════════════════════════════════════════════════════════════════
# 10. GERADOR DE SENHAS / CHAVES
# ══════════════════════════════════════════════════════════════════
def generate_password(length=24, symbols=True) -> str:
    import string
    chars = string.ascii_letters + string.digits
    if symbols: chars += '!@#$%^&*()_+-=[]{}|;:,.<>?'
    return ''.join(secrets.choice(chars) for _ in range(length))

def generate_key(bits=256) -> str:
    return secrets.token_hex(bits // 8)

# ══════════════════════════════════════════════════════════════════
# 11. ANÁLISE / DETECÇÃO
# ══════════════════════════════════════════════════════════════════
def detect_format(text: str) -> str:
    text = text.strip()
    if '|*|' in text and '||' in text: return "Cifra Proprietária"
    try:
        dec = base64.b64decode(text)
        if dec[:8] == b'gAAAAA': return "Fernet Token"
        return "Base64"
    except Exception: pass
    try:
        d = json.loads(text)
        if "mode" in d:
            return d["mode"]
    except Exception: pass
    if all(c in '0123456789abcdefABCDEF' for c in text): return "Hex"
    if text.startswith('-----BEGIN'): return "PEM (RSA/EC Key)"
    return "Desconhecido"

# ══════════════════════════════════════════════════════════════════
# INTERFACE INTERATIVA
# ══════════════════════════════════════════════════════════════════
def print_result(label: str, value: str, color=C.GREEN):
    print(f"\n  {C.DIM}{'─'*60}{C.RESET}")
    print(f"  {C.BOLD}{label}:{C.RESET}")
    print(f"  {color}{value}{C.RESET}")
    print(f"  {C.DIM}{'─'*60}{C.RESET}\n")

def menu_hash():
    print(f"\n  {C.CYAN}Algoritmos: {', '.join(Hasher.ALGOS)}{C.RESET}")
    text = input("  Texto ou caminho de arquivo: ").strip()
    algo = input("  Algoritmo [sha256]: ").strip() or 'sha256'
    if algo not in Hasher.ALGOS:
        err(f"Algoritmo inválido. Use: {', '.join(Hasher.ALGOS)}"); return
    path = Path(text)
    if path.is_file():
        result = Hasher.hash_file(str(path), algo)
        print_result(f"Hash {algo.upper()} do arquivo", result, C.YELLOW)
    else:
        result = Hasher.hash_text(text, algo)
        print_result(f"Hash {algo.upper()}", result, C.YELLOW)

def menu_aes():
    mode = input("  Modo [cbc/gcm] (default cbc): ").strip().lower() or 'cbc'
    op   = input("  Operação [e=encriptar, d=desencriptar]: ").strip().lower()
    if op == 'e':
        text = input("  Texto a encriptar: ").encode()
        pwd  = getpass.getpass("  Senha: ")
        s    = password_strength(pwd)
        print(f"  Força da senha: {s['color']}{s['label']}{C.RESET} ({s['entropy_bits']} bits de entropia)")
        if s['tips']: [warn(t) for t in s['tips']]
        t0 = time.time()
        result = AESCipher.encrypt_cbc(text, pwd) if mode == 'cbc' else AESCipher.encrypt_gcm(text, pwd)
        elapsed = time.time() - t0
        js = json.dumps(result, indent=2)
        print_result(f"AES-256-{mode.upper()} Encriptado", js, C.GREEN)
        ok(f"Tempo: {elapsed*1000:.2f}ms")
    else:
        print("  Cole o JSON encriptado (termine com linha vazia):")
        lines = []
        while True:
            line = input()
            if not line: break
            lines.append(line)
        try:
            data = json.loads('\n'.join(lines))
            pwd  = getpass.getpass("  Senha: ")
            t0   = time.time()
            pt   = AESCipher.decrypt_cbc(data, pwd) if mode == 'cbc' else AESCipher.decrypt_gcm(data, pwd)
            elapsed = time.time() - t0
            print_result("Texto Desencriptado", pt.decode(), C.CYAN)
            ok(f"Tempo: {elapsed*1000:.2f}ms")
        except Exception as e:
            err(f"Falha: {e}")

def menu_chacha():
    op = input("  [e=encriptar, d=desencriptar]: ").strip().lower()
    if op == 'e':
        text = input("  Texto: ").encode()
        pwd  = getpass.getpass("  Senha: ")
        result = ChaCha20Cipher.encrypt(text, pwd)
        print_result("ChaCha20-Poly1305 Encriptado", json.dumps(result, indent=2), C.GREEN)
    else:
        print("  Cole o JSON (linha vazia para finalizar):")
        lines = []
        while True:
            line = input()
            if not line: break
            lines.append(line)
        try:
            data = json.loads('\n'.join(lines))
            pwd  = getpass.getpass("  Senha: ")
            pt   = ChaCha20Cipher.decrypt(data, pwd)
            print_result("Texto Desencriptado", pt.decode(), C.CYAN)
        except Exception as e:
            err(f"Falha: {e}")

def menu_rsa():
    op = input("  [g=gerar par, e=encriptar, d=desencriptar]: ").strip().lower()
    if op == 'g':
        bits = int(input("  Bits [2048/4096] (default 2048): ").strip() or '2048')
        sec("Gerando par RSA, aguarde...")
        t0 = time.time()
        priv, pub = RSACipher.generate_keypair(bits)
        elapsed = time.time() - t0
        priv_file = f"private_{bits}_{int(time.time())}.pem"
        pub_file  = f"public_{bits}_{int(time.time())}.pem"
        Path(priv_file).write_text(priv)
        Path(pub_file).write_text(pub)
        ok(f"Chave privada salva: {priv_file}")
        ok(f"Chave pública salva: {pub_file}")
        ok(f"Tempo de geração: {elapsed:.2f}s")
    elif op == 'e':
        text     = input("  Texto: ").encode()
        pub_file = input("  Arquivo .pem da chave pública: ").strip()
        pub_pem  = Path(pub_file).read_text()
        ct       = RSACipher.encrypt(text, pub_pem)
        print_result("RSA Encriptado (Base64)", ct, C.GREEN)
    else:
        ct       = input("  Ciphertext Base64: ").strip()
        priv_file= input("  Arquivo .pem da chave privada: ").strip()
        priv_pem = Path(priv_file).read_text()
        try:
            pt = RSACipher.decrypt(ct, priv_pem)
            print_result("RSA Desencriptado", pt.decode(), C.CYAN)
        except Exception as e:
            err(f"Falha: {e}")

def menu_classic():
    print(f"\n  {C.CYAN}[1] César  [2] ROT13  [3] Vigenère  [4] XOR  [5] Vernam (OTP){C.RESET}")
    choice = input("  Escolha: ").strip()
    if choice == '1':
        text  = input("  Texto: ")
        shift = int(input("  Deslocamento (1-25): ") or '13')
        op    = input("  [e=encriptar, d=desencriptar]: ").strip().lower()
        res   = ClassicCiphers.caesar_enc(text, shift) if op == 'e' else ClassicCiphers.caesar_dec(text, shift)
        print_result("César", res)
    elif choice == '2':
        text = input("  Texto: ")
        print_result("ROT13", ClassicCiphers.rot13(text))
    elif choice == '3':
        text = input("  Texto: ")
        key  = input("  Chave: ")
        op   = input("  [e/d]: ").strip().lower()
        res  = ClassicCiphers.vigenere_enc(text, key) if op == 'e' else ClassicCiphers.vigenere_dec(text, key)
        print_result("Vigenère", res)
    elif choice == '4':
        text = input("  Texto: ").encode()
        key  = input("  Chave (hex ou texto): ").strip()
        try:
            kb = bytes.fromhex(key)
        except ValueError:
            kb = key.encode()
        ct = ClassicCiphers.xor_enc(text, kb)
        print_result("XOR encriptado (hex)", ct.hex())
        print_result("XOR encriptado (base64)", base64.b64encode(ct).decode())
    elif choice == '5':
        text = input("  Texto: ").encode()
        ct, pad = ClassicCiphers.vernam_enc(text)
        print_result("Vernam ciphertext (hex)", ct.hex())
        print_result("One-Time Pad (hex) — GUARDE ISSO", pad.hex(), C.RED)
        verify = ClassicCiphers.vernam_dec(ct, pad)
        ok(f"Verificação: {verify.decode()}")

def menu_proprietary():
    op = input("  [e=encriptar, d=desencriptar]: ").strip().lower()
    if op == 'e':
        text = input("  Texto: ")
        n_keys = int(input("  Número de chaves (default 2): ").strip() or '2')
        keys = [input(f"  Chave {i+1} (Enter para aleatória): ").strip() or None for i in range(n_keys)]
        keys = [k or secrets.token_hex(2).upper()[:2] for k in keys]
        salt = input("  Salt (Enter para aleatório): ").strip() or None
        result = ProprietaryCipher.encrypt(text, keys, salt)
        print_result("Cifra Proprietária", result, C.MAGENTA)
    else:
        ct = input("  Ciphertext: ").strip()
        try:
            pt = ProprietaryCipher.decrypt(ct)
            print_result("Desencriptado", pt, C.CYAN)
        except Exception as e:
            err(f"Falha: {e}")

def menu_encoding():
    text = input("  Texto ou hex: ").strip()
    op   = input("  [e=codificar, d=decodificar]: ").strip().lower()
    fmt  = input("  Formato [b64/b85/b32/hex] (default b64): ").strip() or 'b64'
    fns = {
        'b64': (Encoding.b64_enc, Encoding.b64_dec),
        'b85': (Encoding.b85_enc, Encoding.b85_dec),
        'b32': (Encoding.b32_enc, Encoding.b32_dec),
        'hex': (Encoding.hex_enc, Encoding.hex_dec),
    }
    if fmt not in fns:
        err("Formato inválido"); return
    enc_fn, dec_fn = fns[fmt]
    if op == 'e':
        result = enc_fn(text.encode())
        print_result(f"{fmt.upper()} Codificado", result)
    else:
        try:
            result = dec_fn(text).decode()
            print_result(f"{fmt.upper()} Decodificado", result, C.CYAN)
        except Exception as e:
            err(f"Erro: {e}")

def menu_generate():
    print(f"\n  {C.CYAN}[1] Senha forte  [2] Chave hex  [3] UUID  [4] Token URL-safe{C.RESET}")
    choice = input("  Escolha: ").strip()
    if choice == '1':
        length = int(input("  Comprimento (default 24): ").strip() or '24')
        sym    = input("  Incluir símbolos? [s/n] (default s): ").strip().lower() != 'n'
        pwd    = generate_password(length, sym)
        s      = password_strength(pwd)
        print_result("Senha Gerada", pwd, C.GREEN)
        print(f"  Força: {s['color']}{s['label']}{C.RESET} | Entropia: {s['entropy_bits']} bits")
    elif choice == '2':
        bits = int(input("  Bits [128/256/512] (default 256): ").strip() or '256')
        print_result(f"Chave Hex {bits}-bit", generate_key(bits), C.YELLOW)
    elif choice == '3':
        import uuid
        print_result("UUID v4", str(uuid.uuid4()), C.CYAN)
    elif choice == '4':
        n = int(input("  Bytes (default 32): ").strip() or '32')
        print_result("Token URL-safe", secrets.token_urlsafe(n), C.CYAN)

def menu_detect():
    text = input("  Cole o texto/ciphertext: ").strip()
    fmt  = detect_format(text)
    print_result("Formato Detectado", fmt, C.MAGENTA)
    print(f"  {C.DIM}Comprimento: {len(text)} chars | Entropia visual: {'alta' if len(set(text))/len(text) > 0.5 else 'baixa'}{C.RESET}")

def interactive_menu():
    print(BANNER)
    missing = check_deps()
    if missing:
        warn(f"Dependências opcionais ausentes: {', '.join(missing)}")
        warn("Instale com: pip install " + ' '.join(missing))
        print()

    MENU = [
        ("🔐", "Cifra Proprietária",    menu_proprietary),
        ("🔒", "AES-256 (CBC/GCM)",     menu_aes),
        ("⚡", "ChaCha20-Poly1305",     menu_chacha),
        ("🗝 ", "Fernet",                lambda: _menu_fernet()),
        ("🔑", "RSA (2048/4096)",       menu_rsa),
        ("🏛 ", "Cifras Clássicas",      menu_classic),
        ("📦", "Encoding (B64/B85/B32/Hex)", menu_encoding),
        ("🔍", "Hashing & HMAC",        menu_hash),
        ("✨", "Gerar Chaves/Senhas",   menu_generate),
        ("🔎", "Detectar Formato",      menu_detect),
    ]

    def _menu_fernet():
        op = input("  [e=encriptar, d=desencriptar]: ").strip().lower()
        if op == 'e':
            text = input("  Texto: ").encode()
            pwd  = getpass.getpass("  Senha: ")
            r    = FernetCipher.encrypt(text, pwd)
            print_result("Fernet Token", json.dumps(r, indent=2), C.GREEN)
        else:
            print("  Cole o JSON (linha vazia para terminar):")
            lines = []
            while True:
                line = input()
                if not line: break
                lines.append(line)
            try:
                d   = json.loads('\n'.join(lines))
                pwd = getpass.getpass("  Senha: ")
                pt  = FernetCipher.decrypt(d, pwd)
                print_result("Desencriptado", pt.decode(), C.CYAN)
            except Exception as e:
                err(f"Falha: {e}")

    MENU[3] = ("🗝 ", "Fernet", _menu_fernet)

    while True:
        print(f"\n{C.BOLD}  {'─'*50}{C.RESET}")
        for i, (icon, name, _) in enumerate(MENU, 1):
            print(f"  {C.DIM}[{C.RESET}{C.CYAN}{i:2}{C.RESET}{C.DIM}]{C.RESET}  {icon}  {name}")
        print(f"  {C.DIM}[ 0]{C.RESET}  ❌  Sair")
        print(f"{C.BOLD}  {'─'*50}{C.RESET}")

        choice = input(f"\n  {C.YELLOW}Escolha uma opção: {C.RESET}").strip()
        if choice == '0':
            print(f"\n  {C.DIM}Bye! Stay secure.{C.RESET}\n")
            break
        try:
            idx = int(choice) - 1
            if 0 <= idx < len(MENU):
                print()
                MENU[idx][2]()
            else:
                err("Opção inválida")
        except (ValueError, KeyboardInterrupt):
            print()
            err("Opção inválida")
        except Exception as e:
            err(f"Erro: {e}")
            import traceback; traceback.print_exc()

# ══════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════
def cli_main():
    parser = argparse.ArgumentParser(
        prog="cryptoforge",
        description="CryptoForge v2.0 — Ferramenta de criptografia multi-algoritmo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python crypto_tool.py --interactive
  python crypto_tool.py hash --text "hello world" --algo sha256
  python crypto_tool.py hash --file myfile.pdf --algo blake2b
  python crypto_tool.py aes enc --text "segredo" --mode gcm
  python crypto_tool.py aes dec --json '{"mode":"AES-256-GCM",...}'
  python crypto_tool.py chacha enc --text "msg"
  python crypto_tool.py classic caesar enc --text "Hello" --shift 3
  python crypto_tool.py classic vigenere enc --text "Hello" --key "KEY"
  python crypto_tool.py encode b64 enc --text "hello"
  python crypto_tool.py keygen --type password --length 32
  python crypto_tool.py detect --text "gAAAAA..."
  python crypto_tool.py proprietary enc --text "meu segredo"
        """
    )
    parser.add_argument('--interactive', '-i', action='store_true', help='Modo interativo (menu)')

    sub = parser.add_subparsers(dest='command')

    # hash
    p_hash = sub.add_parser('hash', help='Hashing e HMAC')
    p_hash.add_argument('--text', help='Texto para hash')
    p_hash.add_argument('--file', help='Arquivo para hash')
    p_hash.add_argument('--algo', default='sha256', choices=Hasher.ALGOS)
    p_hash.add_argument('--hmac-key', help='Chave HMAC (ativa modo HMAC)')
    p_hash.add_argument('--hmac-verify', help='Assinatura HMAC para verificar')

    # aes
    p_aes = sub.add_parser('aes', help='AES-256-CBC/GCM')
    p_aes.add_argument('op', choices=['enc','dec'])
    p_aes.add_argument('--text', help='Texto plaintext')
    p_aes.add_argument('--json', help='JSON encriptado para dec')
    p_aes.add_argument('--mode', default='cbc', choices=['cbc','gcm'])
    p_aes.add_argument('--password', '-p', help='Senha (ou será solicitada)')

    # chacha
    p_cc = sub.add_parser('chacha', help='ChaCha20-Poly1305')
    p_cc.add_argument('op', choices=['enc','dec'])
    p_cc.add_argument('--text')
    p_cc.add_argument('--json')
    p_cc.add_argument('--password', '-p')

    # classic
    p_cl = sub.add_parser('classic', help='Cifras clássicas')
    p_cl.add_argument('cipher', choices=['caesar','rot13','vigenere','xor'])
    p_cl.add_argument('op', choices=['enc','dec'])
    p_cl.add_argument('--text', required=True)
    p_cl.add_argument('--shift', type=int, default=13)
    p_cl.add_argument('--key', default='KEY')

    # encode
    p_enc = sub.add_parser('encode', help='Encoding')
    p_enc.add_argument('fmt', choices=['b64','b85','b32','hex'])
    p_enc.add_argument('op', choices=['enc','dec'])
    p_enc.add_argument('--text', required=True)

    # keygen
    p_kg = sub.add_parser('keygen', help='Gerador de chaves/senhas')
    p_kg.add_argument('--type', choices=['password','hex','token'], default='password')
    p_kg.add_argument('--length', type=int, default=24)
    p_kg.add_argument('--bits',   type=int, default=256)

    # detect
    p_det = sub.add_parser('detect', help='Detectar formato')
    p_det.add_argument('--text', required=True)

    # proprietary
    p_prop = sub.add_parser('proprietary', help='Cifra proprietária')
    p_prop.add_argument('op', choices=['enc','dec'])
    p_prop.add_argument('--text')
    p_prop.add_argument('--keys', nargs='+', default=None)
    p_prop.add_argument('--salt', default=None)

    # rsa
    p_rsa = sub.add_parser('rsa', help='RSA')
    p_rsa.add_argument('op', choices=['gen','enc','dec'])
    p_rsa.add_argument('--text')
    p_rsa.add_argument('--bits', type=int, default=2048)
    p_rsa.add_argument('--pub')
    p_rsa.add_argument('--priv')

    args = parser.parse_args()

    if args.interactive or args.command is None:
        interactive_menu()
        return

    if args.command == 'hash':
        if args.hmac_key:
            target = (args.text or '').encode()
            if args.hmac_verify:
                ok_ = Hasher.hmac_verify(target, args.hmac_key, args.hmac_verify, args.algo)
                print(f"HMAC válido: {ok_}")
            else:
                print(Hasher.hmac_sign(target, args.hmac_key, args.algo))
        elif args.file:
            print(Hasher.hash_file(args.file, args.algo))
        else:
            print(Hasher.hash_text(args.text or '', args.algo))

    elif args.command == 'aes':
        pwd = args.password or getpass.getpass("Senha: ")
        if args.op == 'enc':
            fn = AESCipher.encrypt_gcm if args.mode == 'gcm' else AESCipher.encrypt_cbc
            print(json.dumps(fn((args.text or '').encode(), pwd), indent=2))
        else:
            data = json.loads(args.json or input("JSON: "))
            fn   = AESCipher.decrypt_gcm if args.mode == 'gcm' else AESCipher.decrypt_cbc
            print(fn(data, pwd).decode())

    elif args.command == 'chacha':
        pwd = args.password or getpass.getpass("Senha: ")
        if args.op == 'enc':
            print(json.dumps(ChaCha20Cipher.encrypt((args.text or '').encode(), pwd), indent=2))
        else:
            data = json.loads(args.json or input("JSON: "))
            print(ChaCha20Cipher.decrypt(data, pwd).decode())

    elif args.command == 'classic':
        t = args.text
        c = args.cipher
        o = args.op
        if c == 'caesar':
            print(ClassicCiphers.caesar_enc(t, args.shift) if o == 'enc' else ClassicCiphers.caesar_dec(t, args.shift))
        elif c == 'rot13':
            print(ClassicCiphers.rot13(t))
        elif c == 'vigenere':
            print(ClassicCiphers.vigenere_enc(t, args.key) if o == 'enc' else ClassicCiphers.vigenere_dec(t, args.key))
        elif c == 'xor':
            kb = args.key.encode()
            ct = ClassicCiphers.xor_enc(t.encode(), kb)
            print(ct.hex())

    elif args.command == 'encode':
        fns = {'b64':(Encoding.b64_enc,Encoding.b64_dec),'b85':(Encoding.b85_enc,Encoding.b85_dec),
               'b32':(Encoding.b32_enc,Encoding.b32_dec),'hex':(Encoding.hex_enc,Encoding.hex_dec)}
        ef, df = fns[args.fmt]
        print(ef(args.text.encode()) if args.op == 'enc' else df(args.text).decode())

    elif args.command == 'keygen':
        if args.type == 'password': print(generate_password(args.length))
        elif args.type == 'hex':    print(generate_key(args.bits))
        else:                       print(secrets.token_urlsafe(args.length))

    elif args.command == 'detect':
        print(detect_format(args.text))

    elif args.command == 'proprietary':
        if args.op == 'enc':
            print(ProprietaryCipher.encrypt(args.text or '', args.keys, args.salt))
        else:
            print(ProprietaryCipher.decrypt(args.text or ''))

    elif args.command == 'rsa':
        if args.op == 'gen':
            sec("Gerando par RSA...")
            priv, pub = RSACipher.generate_keypair(args.bits)
            pf = f"private_{args.bits}.pem"; qf = f"public_{args.bits}.pem"
            Path(pf).write_text(priv); Path(qf).write_text(pub)
            ok(f"Privada: {pf}"); ok(f"Pública: {qf}")
        elif args.op == 'enc':
            pub = Path(args.pub).read_text()
            print(RSACipher.encrypt((args.text or '').encode(), pub))
        else:
            priv = Path(args.priv).read_text()
            print(RSACipher.decrypt(args.text or '', priv).decode())

if __name__ == '__main__':
    cli_main()