import tinyec.ec as ec
import tinyec.registry as reg
import json

sk = int(input(),16)     
msk = int("29d8325cb77407dd3bd39158ce89f5c62e5d764e0aa64a6477973560abdaae47", 16)                                                             #input vehicles public key 
a = int("0000000000000000000000000000000000000000000000000000000000000000", 16)
b = int("0000000000000000000000000000000000000000000000000000000000000007", 16)
q = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16)
x = int("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798",16)
y = int("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
n = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)         #elliptic curve parameters set
h = 1

field = ec.SubGroup(q, (x, y), n , 1)
curve = ec.Curve(a, b, field)

p = ec.Point(curve, x, y)                                                                #generator point g and curve is set

pk = sk * p
mpk = msk * p
print(hex(pk.x)+"\n"+hex(pk.y))


u = int("5e5205324863018f4f9454c699eb160688355046e66418647c51b302a90ffd72", 16)          #setting random number for now 

c1 = u * p
c2 = u * pk + pk
c3 = u * mpk + pk


print(hex(c1.x), hex(c1.y))
print(hex(c2.x), hex(c2.y))
print(hex(c3.x), hex(c3.y))

data = {
    "sk" : hex(sk),
    "c1" : [hex(c1.x), hex(c1.y)],
    "c2" : [hex(c2.x), hex(c2.y)],
    "c3" : [hex(c3.x), hex(c3.y)]
}

with open("points.json", "w") as json_file:
    json.dump(data, json_file, indent=4)


#testing with sk = 489d945c50807336b05a645ce8f05e856e7ce3ae1c6eb9798b4ba84c9062d61e
