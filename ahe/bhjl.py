import secrets

import gmpy2
from gmpy2 import mpz


def keygen(k_bits=512):
    n_bits = k_bits << 2
    p_bits = k_bits << 1
    k_2 = 1 << k_bits

    while True:
        p = mpz(secrets.randbits(p_bits - k_bits))
        p = gmpy2.mul(p, k_2) + 1
        if gmpy2.is_prime(p):
            break

    while True:
        q = mpz(secrets.randbits(p_bits)).bit_set(0)
        if p != q and gmpy2.is_prime(q):
            break

    n = p * q

    while True:
        y = mpz(secrets.randbits(n_bits))
        if gmpy2.jacobi(y, p) == -1 and gmpy2.jacobi(y, q) == -1:
            break

    public_key = PublicKey(k_bits, n, y, k_2)
    secret_key = SecretKey(public_key, p)
    return public_key, secret_key


class PublicKey:
    def __init__(self, k, n, y, k_2):
        self.k = k
        self.n = n
        self.y = y
        self.k_2 = k_2

    def encrypt(self, m):
        y = gmpy2.powmod(self.y, m, self.n)
        x = gmpy2.powmod(secrets.randbelow(self.n), self.k_2, self.n)
        c = x * y
        c = gmpy2.f_mod(c, self.n)

        return CipherText(self, c)


class SecretKey:
    def __init__(self, public_key, p):
        self.public_key = public_key
        self.p = p
        self.d = [None] * (public_key.k - 1)
        self.d[0] = gmpy2.powmod(public_key.y, gmpy2.t_div_2exp(p - 1, public_key.k), p)
        self.d[0] = gmpy2.invert(self.d[0], p)

        for i in range(1, public_key.k - 1):
            self.d[i] = gmpy2.powmod(self.d[i - 1], 2, p)

    def decrypt(self, cipher_text):
        c = cipher_text.c
        m, b = mpz(0), mpz(1)
        c = gmpy2.powmod(c, gmpy2.t_div_2exp(self.p - 1, self.public_key.k), self.p)

        for i in range(1, self.public_key.k):
            z = gmpy2.powmod(c, 1 << (self.public_key.k - i), self.p)
            if z != 1:
                m += b
                c *= self.d[i - 1]
                c = gmpy2.f_mod(c, self.p)
            b <<= 1

        if c != 1:
            m += b

        return m


class CipherText:
    def __init__(self, public_key, c):
        self.public_key = public_key
        self.c = c

    def __add__(self, other):
        if isinstance(other, CipherText):
            return self._add_cipher_text(other)
        else:
            return self._add_cipher_text(self.public_key.encrypt(other))

    def __mul__(self, other):
        if isinstance(other, CipherText):
            raise NotImplementedError("Additive HE does not support cipher text multiplication!")

        c = gmpy2.powmod(self.c, other, self.public_key.n)
        return CipherText(self.public_key, c)

    def _add_cipher_text(self, other):
        c = self.c * other.c
        c = gmpy2.f_mod(c, self.public_key.n)
        return CipherText(self.public_key, c)

    def __repr__(self):
        return self.c.digits()
