# bhjl

Simple Python implementation of [Efficient Cryptosystems from 2k-th Power Residue Symbols](https://eprint.iacr.org/2013/435.pdf) with additive homomorphic properites.

## Requirements
* [gmpy2](https://github.com/aleaxit/gmpy) 

## Usage
* Key Generation
```python
from ahe import bhjl

public_key, secret_key = bhjl.keygen(k_bits=512)
```
* Encryption
```python
m1 = 10
m2 = 15

c1 = public_key.encrypt(m1)
c2 = public_key.encrypt(m2)
```
* Additive Homomorphism
    * Addition of cipher texts
    * Addition/Multiplication by a constant
```python
c1 = c1 + c2    # c1 = 25
c1 *= 4         # c1 = 100
c1 += 50        # c1 = 150
```
* Decryption
```python
d = secret_key.decrypt(c1)      # d = 150
```

## Reference
```bibtex
@misc{cryptoeprint:2013:435,
    author = {Fabrice Benhamouda and Javier Herranz and Marc Joye and and Benoît Libert},
    title = {Efficient Cryptosystems From $2^k$-th Power Residue Symbols},
    howpublished = {Cryptology ePrint Archive, Report 2013/435},
    year = {2013},
    note = {\url{https://eprint.iacr.org/2013/435}},
}
```
