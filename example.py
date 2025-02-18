# Example using the Triple Des (T_DES) class
# Can also use the older DES (DES) class

from cui_des import T_DES

tdes = T_DES(mode='ECB', key=b'anappleadaykeepsthedocto')
original = b'hello there'
ct = tdes.encrypt(original)

print(f"Original Text: {original}")
print(f"Cypher Text: {ct}")
print(f"Decrypted text: {tdes.decrypt(ct)}")