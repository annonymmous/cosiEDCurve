## First, some preliminaries that will be needed.

import hashlib

def sha512(s):
    return hashlib.sha512(s).digest()

# Base field Z_p
p = 2**255 - 19

def modp_inv(x):
    return pow(x, p-2, p)

# Curve constant
d = -121665 * modp_inv(121666) % p

# Group order
q = 2**252 + 27742317777372353535851937790883648493

def sha512_modq(s):
    return int.from_bytes(sha512(s), "little") % q

## Then follows functions to perform point operations.

# Points are represented as tuples (X, Y, Z, T) of extended
# coordinates, with x = X/Z, y = Y/Z, x*y = T/Z

def point_add(P, Q):
    A, B = (P[1]-P[0]) * (Q[1]-Q[0]) % p, (P[1]+P[0]) * (Q[1]+Q[0]) % p;
    C, D = 2 * P[3] * Q[3] * d % p, 2 * P[2] * Q[2] % p;
    E, F, G, H = B-A, D-C, D+C, B+A;
    return (E*F, G*H, F*G, E*H);

# Computes Q = s * Q
def point_mul(s, P):
    Q = (0, 1, 1, 0)  # Neutral element
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q

def point_equal(P, Q):
    # x1 / z1 == x2 / z2  <==>  x1 * z2 == x2 * z1
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True

## Now follows functions for point compression.

# Square root of -1
modp_sqrt_m1 = pow(2, (p-1) // 4, p)

# Compute corresponding x-coordinate, with low bit corresponding to
# sign, or return None on failure
def recover_x(y, sign):
    if y >= p:
        return None
    x2 = (y*y-1) * modp_inv(d*y*y+1)
    if x2 == 0:
        if sign:
            return None
        else:
            return 0

    # Compute square root of x2
    x = pow(x2, (p+3) // 8, p)
    if (x*x - x2) % p != 0:
        x = x * modp_sqrt_m1 % p
    if (x*x - x2) % p != 0:
        return None

    if (x & 1) != sign:
        x = p - x
    return x

# Base point
g_y = 4 * modp_inv(5) % p
g_x = recover_x(g_y, 0)
G = (g_x, g_y, 1, g_x * g_y % p)

def point_compress(P):
    zinv = modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")

def point_decompress(s):
    if len(s) != 32:
        raise Exception("Invalid input length for decompression")
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1

    x = recover_x(y, sign)
    if x is None:
        return None
    else:
        return (x, y, 1, x*y % p)

## These are functions for manipulating the private key.

def secret_expand(secret):
    if len(secret) != 32:
        raise Exception("Bad size of private key")
    h = sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= (1 << 254)
    return (a, h[32:])

def secret_to_public(secret):
    (a, dummy) = secret_expand(secret)
    return point_compress(point_mul(a, G))

## The signature function works as below.

def sign(secret, msg):
    a, prefix = secret_expand(secret)
    A = point_compress(point_mul(a, G))
    r = sha512_modq(prefix + msg)
    R = point_mul(r, G)
    Rs = point_compress(R)
    h = sha512_modq(Rs + A + msg)
    s = (r + h * a) % q
    return Rs + int.to_bytes(s, 32, "little")

## And finally the verification function.

def verify(public, msg, signature, Ar=None):
        
    if len(public) != 32:
        raise Exception("Bad public key length")
    if len(signature) != 64:
        Exception("Bad signature length")
    A = point_decompress(public)
    if not A:
        return False
    Rs = signature[:32]
    R = point_decompress(Rs)
    if not R:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= q: return False
    h = sha512_modq(Rs + public + msg)
    sB = point_mul(s, G)
    
    # A = point_add(A, (0,-1, -1, 0))
    if Ar is None:
        hA = point_mul(h, A)
    else:
        print("Ar")
        hA = point_mul(h, point_decompress(Ar))

    return point_equal(sB, point_add(R, hA))

from binascii import unhexlify
secret1 = unhexlify("ce266dfb7c193ac833c16252a30b74bf0384051c769f602c1d7f7b6c81526bbc")
secret2 = unhexlify("c171e7f9b32dc26571ee54e026aabccdba48272384e2493436a85b6b6c713642")
secret3 = unhexlify("c171e7f9b32dc265243534523454353dba48272384e2493436a85b6b6c713642")
msg = b"Hello"

# Priv, Public
a1, prefix1 = secret_expand(secret1)
a2, prefix2 = secret_expand(secret2)
a3, prefix3 = secret_expand(secret3)

A1 = point_mul(a1, G)
A2 = point_mul(a2, G)
A3 = point_mul(a3, G)
A  = point_compress(point_add(A3, point_add(A1, A2)))

# Random
r1 = int("ce266dfb7c193ac833c16252a30b74bf0384051c76e24934367f7b6c81526bbc", 16)
r2 = int("c171e7f9b3193ac833c164e026aabccdba48272384e2493436a85b6b6c713642", 16)
r3 = int("c171e7f9b3123123123544253452345dba48272384e2493436a85b6b6c713642", 16)
r = r1 + r2

assert r1 != 0%q and r1 != 1%q
assert r2 != 0%q and r2 != 1%q

R = point_mul(r, G)
Rs = point_compress(R)
h = sha512_modq(Rs + A + msg)

s1 = (r1 + h*a1) % q
s2 = (r2 + h*a2) % q
s = s1 + s2

sig = Rs + int.to_bytes(s, 32, "little")
# A = A - A2
Ad = point_decompress(A)


T = point_add((0,1,1,0) , A3)
invT = (T[0], -T[1], -T[2], T[3])
Ar  = point_compress(point_add(Ad, invT))
print(verify(A, msg, sig, Ar))