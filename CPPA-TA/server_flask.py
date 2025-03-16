from flask import Flask, request, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
import logging
import base64
import hashlib
from ecdsa.ellipticcurve import Point
from ecdsa.curves import SECP256k1, NIST256p
import redis
import mysql.connector
import struct
import asn1tools

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app)

# Configure logging
logging.basicConfig(level=logging.INFO)

msk = int("29d8325cb77407dd3bd39158ce89f5c62e5d764e0aa64a6477973560abdaae47", 16)


def create_cert(c1_c2,  cid):
    r = redis.Redis(host='localhost', port=6379, db=0)
    r.set(cid, c1_c2)
    asn1_schema = asn1tools.compile_files("ASN/CertificateBase.asn1","oer")
    



def publish_apkey(c1, c2, client_socket):
    c1_x = c1.x().to_bytes(32, byteorder = 'big')
    c1_y = c1.y().to_bytes(32, byteorder = 'big')
    c2_x = c2.x().to_bytes(32, byteorder = 'big')
    c2_y = c2.y().to_bytes(32, byteorder = 'big')

    c1_c2 = c1_x + c1_y + c2_x + c2_y

    cid = hashlib.sha256(c1_c2).digest()
    print("hash: "+cid.hex())

    create_cert(c1_c2, cid)
    client_socket.sendall(cid)
    client_socket.sendall(c1_c2)

    return cid
    


def private_store(c1,c3, cid, pk_bytes, user_id):
    c1_x = c1.x().to_bytes(32, byteorder = 'big')
    c1_y = c1.y().to_bytes(32, byteorder = 'big')
    c3_x = c3.x().to_bytes(32, byteorder = 'big')
    c3_y = c3.y().to_bytes(32, byteorder = 'big')
    
    cnx = mysql.connector.connect(user = 'TAServer', 
                                  password = '123456', 
                                  host = '127.0.0.1', 
                                  database = 'PRIVATE_ID')
    cursor = cnx.cursor()

    insert_query = ("INSERT INTO cid_store" 
                    "(cid, c1_x, c1_y, c3_x, c3_y, current_i)"
                    "VALUES (%(cid)s, %(c1_x)s, %(c1_y)s, %(c3_x)s, %(c3_y)s, %(current_i)s)")
    
    data_cid = {
        'cid': cid,
        'c1_x': c1_x,
        'c1_y': c1_y,
        'c3_x': c3_x,
        'c3_y': c3_y,
        'current_i': 1
    }
    cursor.execute(insert_query, data_cid)
    cnx.commit()
    cursor.close()
    
    
    cursor = cnx.cursor()
    
    insert_query2 = ("INSERT INTO pk_id"
    			"(pk, id_user)"
    			"VALUES (%(pk_bytes)s, %(user_id)s)")
    			
    data_pk_id = {
	'pk_bytes' : pk_bytes,
	'user_id' : user_id,
    }
    cursor.execute(insert_query2, data_pk_id)
    cnx.commit()
    cursor.close()

    cnx.close()

@app.route('/submit', methods=['POST'])
def receive_data():
    try:
        data = request.get_json()
        if not data or 'identity' not in data or 'public_key' not in data:
            return jsonify({'error': 'Missing required fields'}), 400

        identity = data['identity']
        public_key = data['public_key']

        # Ensure the public key is a valid 64-byte bytestring, encoded in Base64
        try:
            data = base64.b64decode(public_key, validate=True)
            if len(data) != 64:
                return jsonify({'error': 'Invalid public key length. Expected a 64-byte (512-bit) value, Base64-encoded.'}), 400
        except Exception:
            return jsonify({'error': 'Invalid public key format. Ensure it is Base64-encoded.'}), 400

        # Log received data (avoid logging sensitive info in production)
        logging.info(f"Received identity: {identity}, valid public_key length: {len(data)} bytes")

        x_bytes = data[:32]
        y_bytes = data[32:]
        x = int.from_bytes(x_bytes, byteorder='big')
        y = int.from_bytes(y_bytes, byteorder='big')

        curve = NIST256p.curve
        pk = Point(curve, x, y)
        mpk = msk * NIST256p.generator
        print(f"Public key recieved \npk_x:{hex(pk.x())}\npk_y:{hex(pk.y())}")
            
        pk_bytes = x_bytes + y_bytes
        byte_representation = struct.pack('I', 1)
        pk_bytes += byte_representation
        hash_result = hashlib.sha256(pk_bytes).hexdigest()
        u = int(hash_result, 16)

        c1 = u * NIST256p.generator
        c2 = (u + 1) * pk
        c3 = u * mpk + pk
        print(f"\nc1_x:{hex(c1.x())}\nc1_y:{hex(c1.y())}")
        print(f"\nc2_x:{hex(c2.x())}\nc2_y:{hex(c2.y())}")
        print(f"\nc3_x:{hex(c3.x())}\nc3_y:{hex(c3.y())}\n\n")
            
        cid = publish_apkey(c1, c2)
        private_store(c1, c3, cid, data, identity)
        
        return jsonify({'message': 'Data received successfully'}), 200
    except Exception as e:
        logging.error(f"Error processing request: {str(e)}")
        return jsonify({'error': 'Server error'}), 500

if __name__ == '__main__':
    # Run on HTTPS with proper certificates in a real deployment
    app.run(host='0.0.0.0', port=5000, ssl_context=('cert.pem', 'key.pem'))
