This project is a complete implementation of RSA Public cryptosystem. Steps followed:
(1)  generate a random n N-bit size odd integer.
(2) use efficient algorithms to determine if the number is prime or not -- primality testing. 
The Miller-Rabin Primality testing algorithm is used to check for primality test.
(3) Using step 1 and 2, two prime numbers, **p and q**, are obtained.
(4) Apply efficient algorithms, Euclid GCD and extended Euclid GCD to generate a public and private keys pairs. **Private key = (d, n) and public key = (e, n)**, where _n = p * q_. 
(5) Encrypt a message that is smaller than n using a public key. Decrypt a message using  a private key. 
