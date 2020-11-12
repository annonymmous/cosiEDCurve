
import os
import binascii
import hashlib
import base58

from ecpy.curves import Curve,Point
from ecpy.keys import ECPublicKey, ECPrivateKey
from ecpy.eddsa import EDDSA

"""
msg = 0x64154e2e9e4b50d654fd9f1202ffba1981b6cb7bd838207a0adedb735de296e4ca9e92ea682d4c684815f9679a8037e0cdd17dc27dd2d77f41f7a4cb8d93a3b7
print(msg)
msg  = msg.to_bytes(64,'big')
print(msg)

signer = EDDSA(hashlib.sha512)
sig = signer.sign(msg,pv_key)
signer.verify(msg,sig,pu_key)
"""


#   Definition of curve
#   For cosigning an Edwards-Curve gets used

ed = Curve.get_curve('Ed25519')

#   Number of signees and threshold number of signees
#   participating in signing process itself

n = 3

#   Creating number m of private public key pairs
#   Private key is a hex int
#   Public key is a Point with x and y coordinate as hex int

ur1 = (os.urandom(32))
pv_key1 = ECPrivateKey(int(ur1.hex(),16), ed)
print(base58.b58encode(pv_key1.d.to_bytes(32,'big')))
pu_key1 = EDDSA.get_public_key(pv_key1)

ur2 = (os.urandom(32))
pv_key2 = ECPrivateKey(int(ur2.hex(),16), ed)
pu_key2 = EDDSA.get_public_key(pv_key2)

ur3 = (os.urandom(32))
pv_key3 = ECPrivateKey(int(ur3.hex(),16), ed)
pu_key3 = EDDSA.get_public_key(pv_key3)

a_1, a_2, a_3 = pv_key1.d, pv_key2.d, pv_key3.d

A_1 = pu_key1.W
A_2 = pu_key2.W
A_3 = pu_key3.W

#   A collective Public Key A generated from the participants N
#   N is defined by n
#   Simple Point addition

A_i = ed.add_point(A_1,A_2)
A_i = ed.add_point(A_i,A_3)

A = A_1 + A_2 + A_3

print(A == A_i)
# A is a Point, A.x is an integer, A.y is an Integer
# Class hierarchy is ECPublicKey, Point, X, Y

print("collective A %s\n" %(A))
print(type(A.x)), print(A.x), print(format(A.x, 'x'))
print("encoded public key  %s\n" %int.from_bytes(ed.encode_point(A), 'big'))
print("encoded public key base58  %s\n" %base58.b58encode(ed.encode_point(A)))

#   A subset of participants M of N who actively participate in the 
#   signature creation. The size of M is denoted by m

m = 2

#   A statement (or message) S

S = 0x800cdec19b9555ea6acda2e23bd0175a7b4f256257cd15e2b7032b1000d09c5c
print(S)
S  = S.to_bytes(32,'big')
# print(S), print(type(S))



#------------------------------------------------------
#   SIGNATURE GENERATION
#------------------------------------------------------

#   For each participant i in M, generate a random secret r_i by 
#   hashing 32 bytes of cryptographycally secure random data. 
#   For efficiency, redue each r_i mod L. Each r_i MUST be re-generated
#   until it is different from 0 mod L or 1 mod L. L is the order of the curve

r_1 = hashlib.sha256(os.urandom(32))
r_2 = hashlib.sha256(os.urandom(32))
r_3 = hashlib.sha256(os.urandom(32))

L = ed.order
print("Order L of curve %s\n" %(L))

r_1 = r_1.to_bytes(32, 'little')
r_2 = r_2.to_bytes(32, 'little')
r_3 = r_3.to_bytes(32, 'little')

r_1 = r_1%L
r_2 = r_2%L
r_3 = r_3%L

"""r_1 = int(r_1.hexdigest(),16)%L
r_2 = int(r_2.hexdigest(),16)%L
r_3 = int(r_3.hexdigest(),16)%L"""

print("random secret r_1 %s\n" %(r_1))
print("type of random secret r_1 %s\n" %(type(r_1)))

#   Computer the integer addition of r of all r_i: r = SUM_{i in M}(r_i)

r = r_1 + r_2 + r_3
print("integer addition r %s\n" %(r))

#   Compute the encoding of the fixed-base scalar multiplication [r]B
#   and call the result R

B = ed.generator
r = r.to_bytes(32, 'little')
R = r*B
print("Result R of scalar multiplication with generator point %s\n" %(R))
print("type of R %s\n" %(type(R)))
print("Point R %s\n" %(R))
# print("Point R.x length %s\n" %(len(R.x))) # integer has no length
print("Point R.x %s\n" %(format(R.x,'x')))
print("Point R.y %s\n" %(format(R.y,'x')))

#   Compute SHA512(R || A || S) and interpret the 64 byte digest as
#   integer c mod L

c = R.x.to_bytes(32, 'big') + R.y.to_bytes(32, 'big') + A.x.to_bytes(32, 'big') + A.y.to_bytes(32, 'big') + S
# c = format(R.x,'x') + format(R.y,'x') + format(A.x,'x') + format(A.y,'x') + format(S,'x')
print("String to be hashed %s\n" %(c))
c = hashlib.sha512(c)
# c = hashlib.sha512(c.encode(encoding='UTF-8'))
c = int(c.hexdigest(),16)%L
print("Sha512 hashed integer c %s\n" %(c))
print("Type of integer c %s\n" %(type(c)))
 
#   For each participant i in M, compute the response s_i = (r_i + c * a_i) mod L

c = c.to_bytes(32, 'little')
s_1 = (r_1 + c * a_1)%L
s_2 = (r_2 + c * a_2)%L

#   Compute the integer addition s of all s_i: s = SUM_{i in M}(s_i).

s = s_1 + s_2 

print("Integer addition result s %s\n" %(s))
print("Type of integer s %s\n" %(type(s)))

#   Initialize a bitmask Z of length n to all zero. For each
#   participant i who is present in N but not in M set the i-th
#   bit of Z to 1, i.e., Z[i] = 1. In our case one byte is enough.
#   Therefore binary 0000 0000 turns into 0000 0011 which is 0x03

print(hex(int('00000100', 2)))

Z = int('00000100', 2)

#   The signature is the concatenation of the encoded point R, the
#   integer s and the bitmask Z, denoted as sig = R || s || Z

sig = format(R.x,'x') + format(R.y,'x') + format(s,'x')  + format(Z,'x')
print("Signature sig %s\n" %(sig))
print("Signature sig length %s\n" %(len(sig)))


#   Interpret integer c

# c = R.x.to_bytes(32, 'big') + R.y.to_bytes(32, 'big') + A.x.to_bytes(32, 'big') + A.y.to_bytes(32, 'big') + S
c = format(R.x,'x') + format(R.y,'x') + format(S,'x')  + format(Z,'x')
c = hashlib.sha512(c)
# c = hashlib.sha512(c.encode(encoding='UTF-8'))
c = int(c.hexdigest(),16)%L
print("Integer c %s\n" %(c))
print("Type of c %s\n" %(type(c)))

#   Initialize a new elliptic curve point T = I. For each bit i in
#   the bitmask that is equal to 1, add the corresponding public key
#   A_i to the point T. Formally T = SUM_{in in N, Z[i] == 1}(A_i)
#   for all i set to 1 in the bitmask.

urT = (os.urandom(32))
pv_keyT = ECPrivateKey(int(urT.hex(),16), ed)
pu_keyT = EDDSA.get_public_key(pv_keyT)

T = pu_keyT.W
print("Elliptic curve point T %s\n" %(T))
print("Type of T %s\n" %(type(T)))

T = T + A_3
print("Elliptic curve point T %s\n" %(T))
print("Type of T %s\n" %(type(T)))

#   Computer the reduced key A' = A - T

A_reduced = A - T
print("Elliptic curve point A' %s\n" %(A_reduced))
print("Type of A' %s\n" %(type(A_reduced)))

#   Check the group equation [8][s]B = [8]R + [8][c]A'


left = 8*s*B
right = 8*R + 8*c*A_reduced

print("Group equation left' %s\n" %(left))
print("Group equation right %s\n" %(right))