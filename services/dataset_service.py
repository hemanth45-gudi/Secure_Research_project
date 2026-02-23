"""
services/dataset_service.py   Dataset Management Service
========================================================
Handles file encryption, RSA signing, and MongoDB storage 
for research datasets.
"""

import datetime
import base64
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from core.db import datasets as ds_col, users as users_col
from core.exceptions import NotFoundException, UnauthorizedException

class DatasetService:
    @staticmethod
    def sign_data(data_bytes, private_key_pem):
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        signature = private_key.sign(
            data_bytes,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return base64.b64encode(signature).decode('utf-8')

    @staticmethod
    def verify_signature(data_bytes, signature_b64, public_key_pem):
        try:
            public_key = serialization.load_pem_public_key(public_key_pem)
            signature  = base64.b64decode(signature_b64)
            public_key.verify(
                signature, data_bytes,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            return True
        except Exception:
            return False

    @staticmethod
    def upload_dataset(owner, description, private_key_pem, files, durations):
        uploaded_data = []
        for i, file in enumerate(files):
            if not file or file.filename == '':
                continue
            
            try:
                duration = int(durations[i])
            except (IndexError, ValueError):
                duration = 1

            fb = file.read()
            fn = secure_filename(file.filename)
            
            # AES Encryption
            aes_key = Fernet.generate_key()
            encrypted_content = Fernet(aes_key).encrypt(fb)
            
            # RSA Signature
            try:
                signature = DatasetService.sign_data(fb, private_key_pem)
            except Exception:
                raise UnauthorizedException("Invalid Private Key provided")

            uploaded_data.append({
                'filename': fn,
                'aes_key': aes_key.decode(),
                'encrypted_content': base64.b64encode(encrypted_content).decode(),
                'signature': signature,
                'expiry_time': datetime.datetime.now() + datetime.timedelta(minutes=duration),
            })

        if uploaded_data:
            ds_col().insert_one({
                'owner': owner,
                'description': description,
                'files': uploaded_data,
                'upload_time': datetime.datetime.now(),
            })
            return len(uploaded_data)
        return 0

    @staticmethod
    def get_all_active_datasets():
        """
        Returns ALL datasets with ALL their files including:
          - is_expired      : True if access time has passed
          - signature_valid : True if file was signed with owner's registered private key
          - expiry          : Full datetime object for display
          - download_data   : Base64 content (only set when accessible = not expired AND sig valid)
          - accessible      : True only when both sig valid AND not expired
        """
        results = []
        now = datetime.datetime.now()

        for ds in ds_col().find():
            owner_doc = users_col().find_one({'username': ds['owner']})
            if not owner_doc:
                continue

            public_key = owner_doc.get('public_key', b'')
            all_files = []

            for f in ds.get('files', []):
                expiry_time = f.get('expiry_time')
                is_expired  = (expiry_time is None) or (now >= expiry_time)

                # Always attempt to decrypt + verify signature for status display
                sig_valid    = False
                download_data = None
                file_size = 0
                try:
                    decrypted = Fernet(f['aes_key'].encode()).decrypt(
                        base64.b64decode(f['encrypted_content'])
                    )
                    file_size = len(decrypted)
                    sig_valid = DatasetService.verify_signature(
                        decrypted, f['signature'], public_key
                    )
                    # Only provide download bytes when fully accessible
                    if sig_valid and not is_expired:
                        download_data = base64.b64encode(decrypted).decode()
                except Exception:
                    pass

                all_files.append({
                    'filename':       f['filename'],
                    'signature_valid': sig_valid,
                    'is_expired':     is_expired,
                    'expiry':         expiry_time,          # datetime or None
                    'download_data':  download_data,        # None when blocked
                    'accessible':     sig_valid and not is_expired,
                    'file_size':      file_size,
                })

            results.append({
                'id':          str(ds['_id']),
                'owner':       ds['owner'],
                'owner_role':  owner_doc.get('role', 'Researcher'),
                'description': ds.get('description', ''),
                'upload_time': ds.get('upload_time'),
                'files':       all_files,
            })

        return results
