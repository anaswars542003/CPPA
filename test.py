from ecdsa.curves import NIST256p
from ecdsa.ellipticcurve import Point

c1_x = int("fa66e680a3652e8b0643dd7706631574b9163f9414aca888136653ff4b2027cd", 16)
c1_y = int("fd26aa22fcf7bd6b9605621a4916207baf6c60a3df9a54942df2a75b9e377c73", 16)

c1 = Point(curve= NIST256p.curve, x = c1_x, y = c1_y)
