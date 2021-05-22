import random
import math


class RSACryptoSystem:
    def __init__(self, bit_size):
        self.p = 0
        self.q = 0
        self.n = self.p * self.q
        self.rP = 0
        self.e = 0
        self.d = 0
        self.nBits = bit_size  # the max prime number limit ( 512 bits - 1024 bits etc)
        self.number = 0
        self.privateKey = (self.d, self.n)
        self.publicKey = (self.e, self.n)
        self.sp = (
            2 ** self.nBits
        )  # prime value start from N bits to users set nBits Size

    def generate_odd_int(self):
        """returns an odd integer with a bit size of nBits"""
        x = [i if i % 2 else i + 1 for i in range(2 ** self.nBits, 2 ** self.nBits + 1)]
        random.shuffle(x)
        return random.choice(
            x
        )  # return a random int from list of random,but shuffled off integers

    def generate_prime(self):
        """generate a prime number"""
        x = self.generate_odd_int()
        print(f"x= {x}")
        p, q = 0, 0
        value = self.miller_rabin_primeTest(x)
        while not (value[0] == "prime"):
            value = self.miller_rabin_primeTest(x)
        return value[0]

    def miller_rabin_primeTest(self, n):
        """Miller - Rabin Primality testing Algs.
        Returns Composite(for sure) or prime with low probable error.
        """

        if n % 2 == 0:  # if n is even => receive input again
            miller_rabin_primeTest()
        else:  # write n-1 = 2^t * u
            n_1 = n - 1

        t = 0
        while n_1 % 2 == 0:
            t += 1
            n_1 = n_1 >> 1  # divide n-1 by 2^1
        u = (n - 1) >> t  # divide n-1 by 2^t
        print(f"t = {t}, u = {u}")

        s = 20  # 100 rounds/trials are performed
        for i in range(s):  # Witness loop perform s trials
            a = generateRandomInt(n)
            x = [modular_exponent(a, u, n)]  # x0

            for j in range(1, t + 1):  # it should iterate t - 1 times
                x.append(x[j - 1] ** 2 % n)
                if x[j] == 1 and x[j - 1] != 1 and x[j - 1] != (n - 1):
                    return "composite"
            if x[t] != 1:
                return "composite"  # n is definitely composite
        return "prime", n

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

    def moduloInverse(self):
        """returns modulo / multiplicative inverse of e such that e*d ≡ 1 (mod rP).
        Where rP  = (p-1) * (q-1).
         rP refers to total number of co-primes relative to n = p*q.
        """
        for d in range(2, self.rP):
            if (self.e * d % self.rP) == 1:
                return d  # return the multiplicative inverse of e

    def generateRSAKeyPairs(self, p, q):
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

        self.privateKey = (self.d, self.p * self.q)
        self.publicKey = (self.e, self.p * self.q)
        # print(f'possible public keys(e)= {self.possiblePublicKeys}')

    def encryptMessage(self, M):
        """compute exponentation M**e mod n efficienly. Binary implementation """
        e = self.publicKey[0]
        n = self.publicKey[1]
        encryptedMessage = self.modular_exponent(M, e, n)  # M ** e % n
        return encryptedMessage

    def decryptMessage(self, C):
        """decrypts a ciphered/encrypted message C.
        compute exponentation M**e efficienly. Tutorial /24/03/2021 @ 1:04:00
        """
        d = self.privateKey[0]
        n = self.privateKey[1]
        decryptedMessage = self.modular_exponent(C, d, n)  # C ** d % n
        return decryptedMessage


def get_Int():
    """returns if input N is an integer"""
    bit_size = int(input("Enter the bit size:"))  # N bits integers or N = 512 bits
    return bit_size


def main():
    # get bit size of the prime numbers
    count = 0
    bit_size = get_Int()
    rsa = RSACryptoSystem(bit_size)  # create RSA object
    # p = rsa.generate_prime()
    # q = rsa.generate_prime()
    # while p == q:
    #     q = rsa.generate_prime()

    p = 113
    q = 97

    rsa.generateRSAKeyPairs(p, q)  # generate private and public keys
    message = 250  # plain text message  , message should be less than n = p*q
    encMessage = rsa.encryptMessage(message)  # encrypted message
    decMessage = rsa.decryptMessage(encMessage)  # decrypted message
    print(f"Decrypted Message = {decMessage}, Original Message: {message}")

    print(
        f"p = {rsa.p}, q = {rsa.q}, private key = {rsa.privateKey}, publicKey = {rsa.publicKey}"
    )


if __name__ == "__main__":
    main()

