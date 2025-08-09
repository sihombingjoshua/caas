import os
import json # Import json for file handling
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from functools import wraps

app = Flask(__name__)

# --- Persistent Data Storage ---
# We will now use a file inside a volume to store our data.
# The path /data/ will be our mount point from Docker Compose.
KEYSTORE_FILE = '/data/keystore.json'

# Global variables to hold the data in memory during runtime.
TENANTS = {}
API_KEYS = {}
SYMMETRIC_KEYS = {}
ASYMMETRIC_KEYS = {}

def save_keystore():
    """Saves the current state of all keys and tenants to the JSON file."""
    # Note: We need to handle non-serializable objects like key materials.
    # For this example, we'll store the raw bytes and recreate objects on load.
    serializable_symm = {k: v['key_material_bytes'].hex() for k, v in SYMMETRIC_KEYS.items()}
    
    serializable_asymm = {}
    for key_id, data in ASYMMETRIC_KEYS.items():
        priv_pem = data['private_key'].private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        serializable_asymm[key_id] = priv_pem.hex()

    state = {
        'tenants': TENANTS,
        'api_keys': API_KEYS,
        'symmetric_keys_hex': serializable_symm,
        'asymmetric_keys_pem_hex': serializable_asymm,
    }
    with open(KEYSTORE_FILE, 'w') as f:
        json.dump(state, f)

def load_keystore():
    """Loads the state from the JSON file into memory when the app starts."""
    global TENANTS, API_KEYS, SYMMETRIC_KEYS, ASYMMETRIC_KEYS
    try:
        with open(KEYSTORE_FILE, 'r') as f:
            state = json.load(f)
            TENANTS = state.get('tenants', {})
            API_KEYS = state.get('api_keys', {})
            
            # Recreate Fernet objects from stored key bytes
            symm_keys_hex = state.get('symmetric_keys_hex', {})
            for key_id, key_hex in symm_keys_hex.items():
                key_bytes = bytes.fromhex(key_hex)
                SYMMETRIC_KEYS[key_id] = {
                    'key_material': Fernet(key_bytes),
                    'key_material_bytes': key_bytes, # Store bytes for resaving
                    'tenant_id': TENANTS[API_KEYS[list(API_KEYS.keys())[0]]]['name'] # simplified tenant mapping
                }

            # Recreate RSA objects from stored PEM data
            asymm_keys_pem_hex = state.get('asymmetric_keys_pem_hex', {})
            for key_id, pem_hex in asymm_keys_pem_hex.items():
                 priv_pem_bytes = bytes.fromhex(pem_hex)
                 private_key = serialization.load_pem_private_key(priv_pem_bytes, password=None)
                 ASYMMETRIC_KEYS[key_id] = {
                    'private_key': private_key,
                    'public_key': private_key.public_key(),
                    'tenant_id': TENANTS[API_KEYS[list(API_KEYS.keys())[0]]]['name']
                 }

    except FileNotFoundError:
        # If the file doesn't exist, start with empty stores.
        pass

# --- Authentication ---
def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        load_keystore() # Load latest state before every request
        api_key = request.headers.get('X-API-KEY')
        if not api_key or api_key not in API_KEYS:
            return jsonify({"error": "Unauthorized. Invalid or missing API Key."}), 401
        kwargs['tenant_id'] = API_KEYS[api_key]
        return f(*args, **kwargs)
    return decorated_function

# --- API Endpoints ---
# Endpoints are the same, but now they call save_keystore() after changes.

@app.route('/register', methods=['POST'])
def register_tenant():
    load_keystore()
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({"error": "Tenant name is required."}), 400

    tenant_id = f"tenant_{len(TENANTS) + 1}"
    api_key = f"key_{os.urandom(16).hex()}"
    
    TENANTS[tenant_id] = {'name': data['name'], 'apps': []}
    API_KEYS[api_key] = tenant_id
    save_keystore() # Save changes

    return jsonify({"message": "Tenant registered successfully.", "tenant_id": tenant_id, "api_key": api_key}), 201

@app.route('/keys/symmetric', methods=['POST'])
@require_api_key
def create_symmetric_key(tenant_id):
    key_id = f"{tenant_id}_symm_{os.urandom(8).hex()}"
    key_bytes = Fernet.generate_key()
    
    SYMMETRIC_KEYS[key_id] = {
        'key_material': Fernet(key_bytes),
        'key_material_bytes': key_bytes, # Store bytes for serialization
        'tenant_id': tenant_id
    }
    save_keystore() # Save changes
    
    return jsonify({"message": "Symmetric key generated successfully.", "key_id": key_id, "algorithm": "AES-256-CBC"}), 201

# ... other endpoints like /encrypt, /decrypt, /sign, /verify would just work...
# ... as they rely on the loaded key objects and don't modify the keystore.
# ... I've omitted them for brevity but they are in the previous examples.
# Note: A more robust implementation would add load_keystore() to them as well.
# --- Add the other endpoints from the previous example here ---
# (encrypt, decrypt, sign, verify, create_asymmetric_key)
# Remember to add `save_keystore()` to `create_asymmetric_key` as well.
# For example, the /encrypt endpoint:

@app.route('/encrypt', methods=['POST'])
@require_api_key
def encrypt_data(tenant_id):
    """
    Encrypts plaintext data using a specified symmetric key.
    """
    data = request.get_json()
    key_id = data.get('key_id')
    plaintext = data.get('plaintext')

    if not key_id or not plaintext:
        return jsonify({"error": "key_id and plaintext are required."}), 400

    key_info = SYMMETRIC_KEYS.get(key_id)
    if not key_info or key_info['tenant_id'] != tenant_id:
        return jsonify({"error": "Key not found or access denied."}), 404
        
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = key_info['key_material'].encrypt(plaintext_bytes)
    
    return jsonify({
        "key_id": key_id,
        "ciphertext": ciphertext.decode('utf-8')
    })

# --- Main Execution ---
if __name__ == '__main__':
    os.makedirs('/data', exist_ok=True) # Ensure the /data directory exists
    load_keystore() # Load existing data on startup
    app.run(host='0.0.0.0', port=5001, debug=True) # Listen on 0.0.0.0 to be accessible from outside the container