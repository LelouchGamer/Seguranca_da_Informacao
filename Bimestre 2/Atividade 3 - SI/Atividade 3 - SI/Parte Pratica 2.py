import secrets
import hashlib
import sympy

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    has_crypto = True
except Exception:
    has_crypto = False

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        exp >>= 1
        base = (base * base) % mod
    return result

def gen_dh_params(bits=512):
    q = sympy.randprime(2**(bits-1), 2**bits - 1)
    p = 2*q + 1
    while not sympy.isprime(p):
        q = sympy.randprime(2**(bits-1), 2**bits - 1)
        p = 2*q + 1
    for g in range(2, 50):
        if mod_exp(g, 2, p) != 1 and mod_exp(g, q, p) != 1:
            return p, g
    return p, 2

def dh_keypair(p, g):
    private = secrets.randbelow(p-3) + 2
    public = mod_exp(g, private, p)
    return private, public

def derive_key_from_shared(shared_int):
    s_bytes = shared_int.to_bytes((shared_int.bit_length()+7)//8, 'big')
    return hashlib.sha256(s_bytes).digest()

def aes_encrypt(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ct

def aes_decrypt(key, blob):
    aesgcm = AESGCM(key)
    nonce = blob[:12]
    ct = blob[12:]
    return aesgcm.decrypt(nonce, ct, None)

def xor_stream_encrypt(key, plaintext):
    key_stream = hashlib.sha256(key).digest()
    out = bytearray()
    kslen = len(key_stream)
    for i, b in enumerate(plaintext):
        out.append(b ^ key_stream[i % kslen])
        if (i+1) % kslen == 0:
            key_stream = hashlib.sha256(key_stream).digest()
    return bytes(out)

def xor_stream_decrypt(key, ciphertext):
    return xor_stream_encrypt(key, ciphertext)

def gen_rsa_keypair(bits=1024):
    p = sympy.randprime(2**(bits//2 -1), 2**(bits//2) -1)
    q = sympy.randprime(2**(bits//2 -1), 2**(bits//2) -1)
    n = p * q
    phi = (p-1)*(q-1)
    e = 65537
    d = sympy.mod_inverse(e, phi)
    pub = (n, e)
    priv = (n, d)
    return pub, priv

def serialize_rsa_pub(pub):
    n, e = pub
    nb = n.to_bytes((n.bit_length()+7)//8, 'big')
    eb = e.to_bytes((e.bit_length()+7)//8, 'big')
    return len(nb).to_bytes(2,'big') + nb + len(eb).to_bytes(2,'big') + eb

def deserialize_rsa_pub(blob):
    ln = int.from_bytes(blob[:2],'big')
    n = int.from_bytes(blob[2:2+ln],'big')
    off = 2+ln
    le = int.from_bytes(blob[off:off+2],'big')
    e = int.from_bytes(blob[off+2:off+2+le],'big')
    return (n, e)

def main():
    print("=== Etapas do algoritmo Diffie-Hellman ===\n")
    p, g = gen_dh_params(bits=256)
    print(f"Parametro publico p: {p}")
    print(f"Parametro publico g: {g}\n")

    a_priv, A_pub = dh_keypair(p, g)
    b_priv, B_pub = dh_keypair(p, g)
    print(f"Alice gera chave privada a: {a_priv}")
    print(f"Alice calcula chave publica A = g^a mod p: {A_pub}")
    print(f"Bob gera chave privada b: {b_priv}")
    print(f"Bob calcula chave publica B = g^b mod p: {B_pub}\n")

    shared_a = mod_exp(B_pub, a_priv, p)
    shared_b = mod_exp(A_pub, b_priv, p)
    print(f"Alice calcula chave compartilhada: {shared_a}")
    print(f"Bob calcula chave compartilhada: {shared_b}")
    print(f"Chaves coincidem? {shared_a == shared_b}\n")

    key_a = derive_key_from_shared(shared_a)
    key_b = derive_key_from_shared(shared_b)

    print("=== Geração de chaves RSA ===")
    rsa_pub, rsa_priv = gen_rsa_keypair(bits=512)
    serialized_pub = serialize_rsa_pub(rsa_pub)
    print(f"Chave publica RSA (n): {rsa_pub[0]}")
    print(f"Chave publica RSA (e): {rsa_pub[1]}")
    print(f"Tamanho da chave publica serializada: {len(serialized_pub)} bytes\n")

    if has_crypto:
        cipher_blob = aes_encrypt(key_a, serialized_pub)
        print("Cifrando chave publica RSA com AES-GCM...")
    else:
        cipher_blob = xor_stream_encrypt(key_a, serialized_pub)
        print("biblioteca cryptography nao encontrada, usando XOR (nao seguro)...")

    if has_crypto:
        recovered = aes_decrypt(key_b, cipher_blob)
    else:
        recovered = xor_stream_decrypt(key_b, cipher_blob)

    rec_pub = deserialize_rsa_pub(recovered)

    print("\n=== Resultado da transmissao protegida ===")
    print(f"Chave publica RSA recuperada (n): {rec_pub[0]}")
    print(f"Chave publica RSA recuperada (e): {rec_pub[1]}")
    print(f"As chaves RSA sao identicas? {rsa_pub == rec_pub}")

if __name__ == "__main__":
    main()
