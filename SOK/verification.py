import tinyec.ec as ec
import tinyec.registry as reg
import json
import hashlib


def verification(c1,c2,msg, R, z, t, field, curve, q, p):
    
    
    e = int("FBF05CAD56C2ED371F0D6AAAAE04ED230FAD14A5CFF1A33519C1B2BD4892DB3C",16)
    

    R2 = z * (c1 + p) + e * c2
    if R == R2:
        print(True)
    else:
        print(False)


with open("points.json", "r") as json_file:
    data = json.load(json_file)
with open("signature.json", "r") as json_file:
    signature = json.load(json_file)

msk = int("24CE776F59C0B30B577B88A407110108469BC1EBCEAEE64AF151ABC690E26DAD", 16)                                                             #input vehicles public key 
a = int("0000000000000000000000000000000000000000000000000000000000000000", 16)
b = int("0000000000000000000000000000000000000000000000000000000000000007", 16)
q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16)
x = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16)
y = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)         #elliptic curve parameters set
h = 1

field = ec.SubGroup(q, (x, y), n, h)
curve = ec.Curve(a, b, field)
p = ec.Point(curve, x, y)     

sk = int(data["sk"],16)
x = int(data["c1"][0],16)
y = int(data["c1"][1],16)
c1 = ec.Point(curve,x,y)
x = int(data["c2"][0],16)
y = int(data["c2"][1],16)
c2 = ec.Point(curve,x,y)

R = ec.Point(curve, int(signature["Rx"],16), int(signature["Ry"], 16))
z = int(signature["z"],16)
t = signature["t"]

verification(c1, c2, signature["msg"], R, z, t, field, curve, q, p)