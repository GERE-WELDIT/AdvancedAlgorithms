import random
import math


class RSACryptoSystem:
    def __init__(self, nBits):
        self.p = 0
        self.q = 0
        self.n = self.p * self.q
        self.rP = 0
        self.e = 0
        self.d = 0
        self.nBits = nBits  # the max prime number limit ( 512 bits - 1024 bits etc)
        self.number = 0
        self.privateKey = (self.d, self.n)
        self.publicKey = (self.e, self.n)
        self.sp = 2**self.nBits   # prime value start from N bits to users set nBits Size

    def isPrime(self, number):
        """checks primality testing: currently, is O(sqrt(n)) time complexity.
        Problem, with big size n(k bits)"""
        self.number = number
        if self.number <= 1:
            return -1, False
        nLimit = math.floor(math.sqrt(self.number))
        for i in range(2, nLimit):
            if self.number % i == 0:
                return self.number, False
        return self.number, True

    def generatePrimeInt(self, nBits=10, foundP=False):
        """generate p, and q prime numbers(needs update.)"""

        if foundP:
            self.sp = self.p + 1
        for i in range(self.sp, 2 ** nBits):
            if self.isPrime(i)[1]:
                if foundP:
                    self.q = self.isPrime(i)[0]  # return the prime number
                    break
                else:
                    self.p = self.isPrime(i)[0]
                    break

    def gcd(self, a, b):
        """returns greater common divisor of a and b."""
        if b == 0:
            return a
        return self.gcd(b, a % b)

    def moduloInverse(self):
        """returns modulo / multiplicative inverse of e such that e*d ≡ 1 (mod rP).
        Where rP  = (p-1) * (q-1).
        """
        for d in range(2, self.rP):
            if (self.e * d % self.rP) == 1:
                return d  # return the multiplicative inverse of e

    def generateRSAKeyPairs(self):
        """get a small e which is a relative prime to rp = (p-1)*(q-1).
        Then, find generate private and public keys.
        """
        self.rP = (self.p - 1) * (self.q - 1)   # get the co-prime, Q(n)
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
        e = self.publicKey[0]
        n = self.publicKey[1]
        encryptedMessage = M ** e % n
        return encryptedMessage

    def decryptMessage(self, C):
        """decrypts a ciphered/encrypted message C"""
        d = self.privateKey[0]
        n = self.privateKey[1]
        decryptedMessage = C ** d % n
        return decryptedMessage


def main():
    N = 6  # N bits integers or N = 512 bits
    rsa = RSACryptoSystem(N)  # create rsa object ( Alice's RSA)

    rsa.generatePrimeInt(nBits=2*N)  # get first prime number :p
    rsa.generatePrimeInt(nBits=2*N, foundP=True)  # get second prime: q
    rsa.generateRSAKeyPairs()  # generate private and public keys

    message = 250  # plain text message  , message should be less than n = p*q
    encMessage = rsa.encryptMessage(message)   # encrypted message
    decMessage = rsa.decryptMessage(encMessage)    # decrypted message
    print(f'decypted Message = {decMessage}')

    print(f"p = {rsa.p}, q = {rsa.q}, private key = {rsa.privateKey}, publicKey = {rsa.publicKey}")


if __name__ == '__main__':
    main()

    # next step: create two rsa objects:
    # rsa_alice and rsa_bob. have them them their keys.
    # send message between them.
