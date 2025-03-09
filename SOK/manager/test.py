from ecdsa import NIST256p, ellipticcurve
from ecdsa import SigningKey

# Get the generator point (G) of the NIST P-256 curve
curve = NIST256p.curve
p = NIST256p.generator
