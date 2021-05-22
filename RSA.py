import random
import math
import sys


class RSACryptoSystem:
    def __init__(self):
        self.p = 0
        self.q = 0
        self.n = self.p * self.q
        self.rP = 0
        self.e = 0
        self.d = 0
        self.nBits = 5  # the max prime number limit ( 512 bits - 1024 bits etc)
        self.number = 0
        self.privateKey = (self.d, self.n)
        self.publicKey = (self.e, self.n)
        self.sp = (
            2 ** self.nBits
        )  # prime value start from N bits to users set nBits Size

    def generate_odd_int(self):
        """returns an odd integer with a bit size of nBits"""
        # Select odd numbers only in the range of 2^(n-1) to (2^n) -1
        x = random.randrange((2 << (self.nBits - 2)) + 1, 2 << (self.nBits - 1), 2)
        return x

    def generatePrimes(self):
        """generate a prime number"""
        p, q = 0, 0
        print("n_bits", self.nBits)
        for i in range(1, 3):
            x = self.generate_odd_int()
            value = self.miller_rabin_primeTest(x)
            while not (value == "prime" and x != p):
                x = self.generate_odd_int()
                value = self.miller_rabin_primeTest(x)
            if i == 1:
                p = x
            else:
                q = x

        return p, q

    def miller_rabin_primeTest(self, n):
        """Miller - Rabin Primality testing Algs.
        Returns Composite(for sure) or prime with low probable error.
        """
        # write n-1 = 2^t * u
        n_1 = n - 1

        t = 0
        while n_1 % 2 == 0:
            t += 1
            n_1 = n_1 >> 1  # divide n-1 by 2^1
        u = (n - 1) >> t  # divide n-1 by 2^t, faster
        print(f"t = {t}, u = {u}")

        s = 20  # 100 rounds/trials are performed
        for i in range(s):  # Witness loop perform s trials
            a = self.generateRandomInt(n)
            x = [self.modular_exponent(a, u, n)]  # x0

            for j in range(1, t + 1):  # it should iterate t - 1 times
                x.append(x[j - 1] ** 2 % n)
                if x[j] == 1 and x[j - 1] != 1 and x[j - 1] != (n - 1):
                    return "composite"
            if x[t] != 1:
                return "composite"  # n is definitely composite
        return "prime"

    def modular_exponent(self, a, c, n):
        """required task is (a^c)mod n"""
        r = 1  # remainder after each iteration of modular exponentiation
        b = (bin(c))[2:]  # binary respresentation of b
        for i in b:
            r = r * r % n
            if int(i) == 1:
                r = r * a % n
        return r

    def generateRandomInt(self, n):
        """returns a random integer a such that 2 <= a <= n-2 """
        return random.randint(1, n - 2)

    def gcd(self, a, b):
        """returns greater common divisor of a and b."""
        if b == 0:
            return a
        return self.gcd(b, a % b)

    def etx_gcd(self, a, b):
        """ extended euclid Alg."""
        if b == 0:
            return a, 1, 0
        gcd, x, y = self.etx_gcd(b, a % b)
        gcd, x, y = gcd, y, x - a // b * y
        return gcd, x, y

    def moduloInverse(self, e, rP):
        """ return integer d such that d = m^-1 mod n =  gcd(m*d, rP) == 1 """
        gcd, x, y = self.etx_gcd(e, rP)
        if gcd == 1:
            return x % rP
        return False  # in case no inverse

    def generateKeyPairs(self, p, q):
        """get a small e which is a relative prime to rp = (p-1)*(q-1).
        Then, find generate private and public keys.
        """
        self.p = p
        self.q = q
        print("p,q =", p, q)

        self.rP = (self.p - 1) * (self.q - 1)  # get the co-prime, Q(n)
        possiblePublicKeys = []
        for e in range(2, self.rP):
            if self.gcd(e, self.rP) == 1:
                possiblePublicKeys.append(e)
        # pick random e from possible public keys
        self.e = random.choice(possiblePublicKeys)

        self.d = self.moduloInverse()
        while not self.d:  # if the picked e has no inverse
            self.e = random.choice(possiblePublicKeys)
            self.d = self.moduloInverse()

        self.privateKey = (self.d, self.p * self.q)
        self.publicKey = (self.e, self.p * self.q)
        # print(f'possible public keys(e)= {self.possiblePublicKeys}')
        return self.privateKey, self.publicKey

    def encryptMessage(self, M, e, n):
        """compute exponentation M**e mod n efficienly. Binary implementation """

        encryptedMessage = self.modular_exponent(M, e, n)  # M ** e % n
        return encryptedMessage

    def decryptMessage(self, C, d, n):
        """decrypts a ciphered/encrypted message C.
        compute exponentation M**e efficienly. Tutorial /24/03/2021 @ 1:04:00
        """
        decryptedMessage = self.modular_exponent(C, d, n)  # C ** d % n
        return decryptedMessage

    def get_bitSize(self):
        """returns if input N is an integer"""
        bit_size = int(input("Enter the bit size:"))  # N bits integers or N = 512 bits
        self.nBits = bit_size


def main():
    # get bit size of the prime numbers
    rsa = RSACryptoSystem()  # create RSA object

    choice = input(
        "Enter 'e' for encryption,'d' for decryption or 'g' to generate keys:"
    )
    if choice == "e":
        message, e, n = input("inter message, e, and n:").split(" ")
        message, e, n = int(message), int(e), int(n)

        encyptedMessage = rsa.encryptMessage(message, e, n)
        print(f" Encrypted Message = {encyptedMessage}")

    elif choice == "d":
        message, d, n = input("Enter Message, d, and n:").split(" ")
        message, d, n = int(message), int(d), int(n)
        decryptedMessage = rsa.decryptMessage(message, d, n)
        print(f" Encrypted Message = {decryptedMessage}")

    elif choice == "g":
        # get bit_size input
        rsa.get_bitSize()

        p, q = rsa.generatePrimes()
        print(f"p {p},q = {q}")

        privateKey, publicKey = rsa.generateKeyPairs(p, q)
        print(f"private key : {privateKey}, public key : {publicKey}")
    elif choice == "x":
        sys.exit()
    else:
        print("Enter correct choice.")


if __name__ == "__main__":
    while True:
        main()

