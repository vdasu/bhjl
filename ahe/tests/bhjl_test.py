import unittest
import secrets

from ahe import bhjl


class BHJLTest(unittest.TestCase):

    def setUp(self):
        self.pk, self.sk = bhjl.keygen(k_bits=secrets.choice(range(16, 1025)))

    def testEncryptDecrypt(self):
        plain_text = secrets.randbits(self.pk.k)
        cipher_text = self.pk.encrypt(plain_text)
        decrypted_text = self.sk.decrypt(cipher_text)
        self.assertEqual(plain_text, decrypted_text)

    def testAheCipherTextAddition(self):
        plain_text1 = secrets.randbits(self.pk.k // 2)
        plain_text2 = secrets.randbits(self.pk.k // 2)
        cipher_text1 = self.pk.encrypt(plain_text1)
        cipher_text2 = self.pk.encrypt(plain_text2)
        cipher_text1 += cipher_text2
        decrypted_text = self.sk.decrypt(cipher_text1)
        self.assertEqual(decrypted_text, plain_text1 + plain_text2)

    def testAheConstantAddition(self):
        constant = secrets.randbits(self.pk.k // 2)
        plain_text = secrets.randbits(self.pk.k // 2)
        cipher_text = self.pk.encrypt(plain_text)
        cipher_text += constant
        decrypted_text = self.sk.decrypt(cipher_text)
        self.assertEqual(decrypted_text, plain_text + constant)

    def testAheConstantMultiplication(self):
        constant = secrets.randbits(self.pk.k // 2)
        plain_text = secrets.randbits(self.pk.k // 2)
        cipher_text = self.pk.encrypt(plain_text)
        cipher_text *= constant
        decrypted_text = self.sk.decrypt(cipher_text)
        self.assertEqual(decrypted_text, plain_text * constant)

    def testAheCipherTextMultiplication(self):
        plain_text1 = secrets.randbits(self.pk.k // 2)
        plain_text2 = secrets.randbits(self.pk.k // 2)
        cipher_text1 = self.pk.encrypt(plain_text1)
        cipher_text2 = self.pk.encrypt(plain_text2)
        with self.assertRaises(NotImplementedError):
            cipher_text1 *= cipher_text2


if __name__ == '__main__':
    unittest.main()
