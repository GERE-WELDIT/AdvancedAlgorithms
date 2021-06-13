This project is a complete implementation of RSA Public cryptosystem.
Steps followed to implement RSA Public Cryptosystem:

(1) generate a random n N-bit size odd integer.\n
(2) use efficient algorithms to determine if the number is prime or not -- primality testing.\n
The Miller-Rabin Primality testing algorithm is used to check for primality test.\n
(3) Using step 1 and 2, two prime numbers, **p and q**, are obtained.\n
(4) Apply efficient algorithms, Euclid GCD and extended Euclid GCD to generate a public and private keys pairs. **Private key = (d, n) and public key = (e, n)**, where **n = p \* q**.\n
(5) Encrypt a message that is smaller than n using a public key. Decrypt a message using a private key.
