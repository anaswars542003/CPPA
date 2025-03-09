import socket
import hashlib
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1
import redis



msk = int("29d8325cb77407dd3bd39158ce89f5c62e5d764e0aa64a6477973560abdaae47", 16)
sk = int("909DD1B5E1537EAC3E8E97BF58088371E43669C5D402C7E3F35ABFDA3549A5E1", 16)
curve = SECP256k1.curve
pk = sk * SECP256k1.generator
mpk = msk * SECP256k1.generator
u = int("5e5205324863018f4f9454c699eb160688355046e66418647c51b302a90ffd72", 16)
c1 = u * SECP256k1.generator
c2 = (u + 1) * pk
c3 = u * mpk + pk

c1_x = hex(c1.x())
c1_y = hex(c1.y())
c2_x = hex(c2.x())
c2_y = hex(c2.y())
pk_x = pk.x().to_bytes(32, byteorder = 'big')
pk_y = pk.y().to_bytes(32, byteorder = 'big')
c1_x = c1.x().to_bytes(32, byteorder = 'big')
c1_y = c1.y().to_bytes(32, byteorder = 'big')
c2_x = c2.x().to_bytes(32, byteorder = 'big')
c2_y = c2.y().to_bytes(32, byteorder = 'big')

print(f"x:{pk_x.hex()} \n y: {pk_y.hex()}")
print(f"c1 : {c1_x.hex()} \n {c1_y.hex()}")
print(f"c2 : {c2_x.hex()} \n {c2_y.hex()}")
concat = c1_x + c1_y + c2_x + c2_y
print(f"concat : {concat.hex()}")
