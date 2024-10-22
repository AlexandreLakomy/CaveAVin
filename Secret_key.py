import os
import binascii

# Génère une clé secrète de 32 octets et l'encode en hexadécimal
secret_key = binascii.hexlify(os.urandom(32)).decode()
print(secret_key)
