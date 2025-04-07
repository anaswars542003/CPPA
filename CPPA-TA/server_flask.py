from flask import Flask, request, jsonify
import mysql.connector
from ecdsa.ellipticcurve import Point
from ecdsa.curves import  NIST256p
from ecdsa import SigningKey
from ecdsa.util import sigdecode_string
import struct
import hashlib
from server import create_cert
from flask import Flask, request, jsonify
import binascii
import base64
import time
import asn1tools

msk = int("29d8325cb77407dd3bd39158ce89f5c62e5d764e0aa64a6477973560abdaae47", 16)

app = Flask(__name__)

def get_oer_from_db(cid):
    """Fetch the OER from the database based on the given CID."""
    conn = mysql.connector.connect(
                                  user = 'TAServer', 
                                  password = '123456', 
                                  host = '127.0.0.1', 
                                  database = 'PRIVATE_ID'
                                )
    cursor = conn.cursor()
    cursor.execute("SELECT oer FROM certificates WHERE cid = %s", (cid,))
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else None

def verify_signature(cid, signature_bytes):
    return True


def create_cert(c1_c2,  cid):
    
    asn1_schema = asn1tools.compile_files("ASN/CertificateBase.asn1","oer")

    to_be_signed_data = {
        "id" :  cid,
        "validity" : {"end" : int(time.time()) +7200 },
        "anonymousPK" : c1_c2
    }
    encoded_tobe_signed = asn1_schema.encode('ToBeSignedCertificate', to_be_signed_data)

    hash_digest = hashlib.sha256(encoded_tobe_signed).digest()
    private_key = SigningKey.from_secret_exponent(msk, curve=NIST256p)
    public_key = private_key.get_verifying_key()

    signature = private_key.sign_digest_deterministic(hash_digest)
    r, s = sigdecode_string(signature, NIST256p.order)

    signature_data = (
        "ecdsaNistP256Signature", 
        {
            "rSig": {
                "x": r.to_bytes(32, byteorder='big')
                
            },
            "sSig": s.to_bytes(32, byteorder='big')
        }
    )

    certificate_data = {
        "version": 3,
        "tobeSignedData": to_be_signed_data,
        "signature": signature_data
    }

    encoded_certificate = asn1_schema.encode('CertificateBase', certificate_data)
    

    cnx = mysql.connector.connect(user = 'TAServer', 
                                  password = '123456', 
                                  host = '127.0.0.1', 
                                  database = 'PRIVATE_ID')
    
    cursor = cnx.cursor()
    #encoded_certificate oer( BLOB )
    #cid   cid
    expiry_time = int(time.time()) + 7200  # 2 hours from now (UNIX timestamp)
    current_time = int(time.time())

    # Convert expiry_time to MySQL TIMESTAMP format
    expiry_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(expiry_time))
    cur_timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(current_time))

    sql = "INSERT INTO certificates (cid, oer, expiry_time, created_at) VALUES (%s, %s, %s, %s)"
    values = (cid, encoded_certificate, expiry_timestamp, cur_timestamp)
    cursor.execute(sql, values)
    cnx.commit()
    cnx.close()
   

def publish_apkey(c1, c2):
    c1_x = c1.x().to_bytes(32, byteorder = 'big')
    c1_y = c1.y().to_bytes(32, byteorder = 'big')
    c2_x = c2.x().to_bytes(32, byteorder = 'big')
    c2_y = c2.y().to_bytes(32, byteorder = 'big')

    c1_c2 = c1_x + c1_y + c2_x + c2_y

    cid = hashlib.sha256(c1_c2).digest()
    print("hash: "+cid.hex())

    create_cert(c1_c2, cid)
    return cid

def private_store(c1, c3, cid, cur_i):
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
        'current_i': cur_i
    }
    cursor.execute(insert_query, data_cid)
    cnx.commit()
    cursor.close()


def trace_id(cid):
    cnx = mysql.connector.connect(user = 'TAServer',
                                  password = '123456',
                                  host = '127.0.0.1',
                                  database = 'PRIVATE_ID')
    
    cursor = cnx.cursor()

    find_id_query = ("SELECT c1_x, c1_y, c3_x, c3_y, current_i FROM cid_store WHERE cid = %(cid)s")
    cursor.execute(find_id_query, {'cid':cid})

    result = cursor.fetchone()
    
    c1_x, c1_y , c3_x, c3_y, current_i = result
    
    cursor.close()
    

    curve = NIST256p.curve
    
    c1_x = int.from_bytes(c1_x, byteorder = 'big')
    c1_y = int.from_bytes(c1_y, byteorder = 'big')
    c3_x = int.from_bytes(c3_x, byteorder = 'big')
    c3_y = int.from_bytes(c3_y, byteorder = 'big')
    c1_y = -c1_y
   
    c1 = Point(curve, c1_x, c1_y)
    c3 = Point(curve, c3_x, c3_y)
    pk = c3 + (msk * c1)

    
    pk_x = pk.x()
    pk_y = pk.y()
    
    pk_x = pk_x.to_bytes(32, byteorder = 'big')
    pk_y = pk_y.to_bytes(32, byteorder = 'big')
    
    pk_bytes = pk_x + pk_y
    cursor = cnx.cursor()
    find_id_query2 = ("SELECT pk, id_user  FROM pk_id WHERE pk = %(pk_bytes)s")
    cursor.execute(find_id_query2, {'pk_bytes':pk_bytes})
    result = cursor.fetchone()
    cursor.close()
    cnx.close()
    
    t, user_id = result
    print(f"user id : {user_id}")
    return (pk_bytes, current_i)


@app.route('/get_cert', methods=['POST'])
def get_oer():
    """API endpoint to fetch OER by CID."""
    data = request.get_json()
    if not data or 'cid' not in data:
        return jsonify({"error": "Missing CID"}), 400
    
    cid = data['cid']
    try:
        cid_bytes = bytes.fromhex(cid)  # Assuming CID is sent as a hex string
        if len(cid_bytes) != 32:
            return jsonify({"error": "Invalid CID length"}), 400
    except ValueError:
        return jsonify({"error": "Invalid CID format"}), 400
    
    oer = get_oer_from_db(cid_bytes)
    if oer is None:
        return jsonify({"error": "CID not found"}), 404
    
    return oer, 200, {'Content-Type': 'application/octet-stream'}

@app.route('/get_new_apk', methods=['POST'])
def get_new_apk():
    """API endpoint to get a new APK based on CID and signature."""
    data = request.get_json()
    if not data or 'cid' not in data or 'signature' not in data:
        return jsonify({"error": "Missing CID or signature"}), 400
    
    try:
        # Decode base64 CID
        cid_base64 = data['cid']
        cid_bytes = base64.b64decode(cid_base64)
        
        # Validate CID length (32 bytes)
        if len(cid_bytes) != 32:
            return jsonify({"error": "Invalid CID length"}), 400
            
        # Get signature
        signature_base64 = data['signature']
        signature_bytes = base64.b64decode(signature_base64)
        
        # Validate signature length (65 bytes)
        if len(signature_bytes) != 65:
            return jsonify({"error": "Invalid signature length"}), 400
            
        if not verify_signature(cid_bytes, signature_bytes):
            return jsonify({"error":"Invalid signature"}) , 400
        
        #needs current index and public key of the sender
        pk_bytes , cur_i = trace_id(cid_bytes)

        x_bytes = pk_bytes[:32]
        y_bytes = pk_bytes[32:]
        x = int.from_bytes(x_bytes, byteorder='big')
        y = int.from_bytes(y_bytes, byteorder='big')


        curve = NIST256p.curve
        pk = Point(curve, x, y)
        mpk = msk * NIST256p.generator
        print(f"Public key \npk_x:{hex(pk.x())}\npk_y:{hex(pk.y())}")

        cur_i += 1
        byte_representation = struct.pack('I', cur_i)
        pk_bytes += byte_representation
        hash_result = hashlib.sha256(pk_bytes).hexdigest()
        u = int(hash_result, 16)
        c1 = u * NIST256p.generator
        c2 = (u + 1) * pk
        c3 = u * mpk + pk
        print(f"\nc1_x:{hex(c1.x())}\nc1_y:{hex(c1.y())}")
        print(f"\nc2_x:{hex(c2.x())}\nc2_y:{hex(c2.y())}")
        print(f"\nc3_x:{hex(c3.x())}\nc3_y:{hex(c3.y())}\n\n")

        #publish c1, c3
        cid = publish_apkey(c1, c2)

        #publish cert
        private_store(c1, c3, cid, cur_i)




        return ({"changed":1}) , 200

        
    except base64.binascii.Error:
        return jsonify({"error": "Invalid base64 encoding"}), 400
    except Exception as e:
        return jsonify({"error": f"Processing error: {str(e)}"}), 500

if __name__ == '__main__':
    app.run(debug=True)
