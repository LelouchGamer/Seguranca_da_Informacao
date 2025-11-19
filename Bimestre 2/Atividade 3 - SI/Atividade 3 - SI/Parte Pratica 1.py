import secrets
import sympy

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        exp = exp // 2
        base = (base * base) % mod
    return result

def diffie_hellman():
    p = sympy.randprime(1000, 10000)
    g = secrets.randbelow(p - 2) + 2

    a = secrets.randbelow(p - 2) + 2
    b = secrets.randbelow(p - 2) + 2
    A = mod_exp(g, a, p)
    B = mod_exp(g, b, p)

    S_alice = mod_exp(B, a, p)
    S_bob = mod_exp(A, b, p)

    print("Parametro publico p:", p)
    print("Gerador g:", g)
    print("Chave privada de Alice:", a)
    print("Chave publica de Alice:", A)
    print("Chave privada de Bob:", b)
    print("Chave publica de Bob:", B)
    print("Chave secreta calculada por Alice:", S_alice)
    print("Chave secreta calculada por Bob:", S_bob)

    if S_alice == S_bob:
        print("Chave compartilhada confirmada:", S_alice)
    else:
        print("Erro: chaves diferentes")

diffie_hellman()
