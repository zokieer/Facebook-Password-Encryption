#https://github.com/zokieer/Facebook-Password-Encryption
import os, time, struct, base64, urllib.request, urllib.parse, json
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TOKEN = "" # Queen never cry :>
USER_AGENT = ""
BASE_URL = "" # Queen never cry :>

def fetch_key():
    body = urllib.parse.urlencode({
        "version": "2",
        "flow": "CONTROLLER_INITIALIZATION",
        "locale": "en_US",
        "client_country_code": "US",
        "method": "GET",
        "fb_api_req_friendly_name": "pwdKeyFetch",
        "fb_api_caller_class": "Fb4aAuthHandler",
        "access_token": TOKEN,
    }).encode()
    req = urllib.request.Request(BASE_URL, data=body, method="POST",
                                 headers={"User-Agent": USER_AGENT, "X-FB-Friendly-Name": "pwdKeyFetch",
                                          "Content-Type": "application/x-www-form-urlencoded"})
    j = json.load(urllib.request.urlopen(req, timeout=15))
    return j["key_id"], j["public_key"], j["seconds_to_live"]


def encrypt_fb4a(password, key_id, public_key_pem, ts=None):
    ts = ts or str(int(time.time()))
    aes_key, nonce = os.urandom(32), os.urandom(12)
    ct_tag = AESGCM(aes_key).encrypt(nonce, password.encode(), ts.encode())
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]
    enc_key = serialization.load_pem_public_key(public_key_pem.encode()).encrypt(aes_key, padding.PKCS1v15())
    blob = bytes([1, key_id & 0xff]) + nonce + struct.pack('<H', len(enc_key)) + enc_key + tag + ciphertext
    return "#PWD_FB4A:2:%s:%s" % (ts, base64.b64encode(blob).decode())


if __name__ == "__main__":
    key_id, pub, ttl = fetch_key()
    print("key_id=%d  ttl=%ds" % (key_id, ttl))
    print(encrypt_fb4a("123456", key_id, pub))
