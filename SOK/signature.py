import tinyec.ec as ec
import tinyec.registry as reg
import json
import hashlib

with open("points.json", "r") as json_file:
    data = json.load(json_file)


def genProof(sk,c1,c2,msg,t, field, curve, q, n):

    r = int("9b1c1e0736da4340867b05110969925810d60b2480cf33e320bdf09468c4a119", 16)   #setting random number not so randomly
    R = r*(c1 + p)
    print(hex(R.x), hex(R.y))
    
    e = int("FBF05CAD56C2ED371F0D6AAAAE04ED230FAD14A5CFF1A33519C1B2BD4892DB3C",16)
    z = (r - (e * sk)) % n
    data = {
        "msg" : msg,
        "t" : t,
        "hash": hex(e),
        "Rx" : hex(R.x),
        "Ry" : hex(R.y),
        "z" : hex(z)
    }
    with open("signature.json", "w") as json_file:
        json.dump(data, json_file, indent=4)


msk = int("24CE776F59C0B30B577B88A407110108469BC1EBCEAEE64AF151ABC690E26DAD", 16)                                                             #input vehicles public key 
a = int("0000000000000000000000000000000000000000000000000000000000000000", 16)
b = int("0000000000000000000000000000000000000000000000000000000000000007", 16)
q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16)
x = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16)
y = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)         #elliptic curve parameters set
h = 1

field = ec.SubGroup(q, (x, y), n , 1)
curve = ec.Curve(a, b, field)
p = ec.Point(curve, x, y)     


sk = int(data["sk"],16)
x = int(data["c1"][0],16)
y = int(data["c1"][1],16)
c1 = ec.Point(curve,x,y)
x = int(data["c2"][0],16)
y = int(data["c2"][1],16)
c2 = ec.Point(curve,x,y)
x = int(data["c3"][0],16)
y = int(data["c3"][1],16)
c3 = ec.Point(curve,x,y)

print("c1:  ", hex(c1.x), hex(c1.y))
print("c2:  ", hex(c2.x), hex(c2.y))

msg = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
t = 0

genProof(sk,c1,c2,msg,t, field , curve, q, n)



