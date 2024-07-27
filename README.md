<p align="center">
  <a href="https://github.com/1nfocalypse/ROXy">
	<img alt="ROXy" src="https://i.imgur.com/pnWe1lu.png"/>
  </a>
</p>
<p align="center">
  <a href="https://choosealicense.com/licenses/gpl-3.0/">
  	<img alt="License: GPL-3.0" src="https://img.shields.io/github/license/1nfocalypse/ROXy"/>
  </a>
</p>
<h2 align="center">ROXy</h3>
<h3 align="center">
  Exploring Plausibly Deniable Encryption via Toy Implementation
</h2>
<p align="center">
  By <a href="https://github.com/1nfocalypse">1nfocalypse</a>
</p>


## Background
Most proponents of cryptography are familiar with a hypothetical situation in which somebody forces another to give up their keys, i.e. an authoritarian state demanding a journalist to give up their keys. While the dogmatic argument is to respond "I'll never give up my keys!", it's more prudent to 
consider a technical workaround. Thus is born plausibly deniable encryption (PDE), in which the agent under duress is able to provide a false key that decrypts the known ciphertext into something benign. While this form of cryptography is uncommon for a multitude of reasons, it's an interesting 
bit of technology that acknowledges some of the weaknesses of traditional cryptographic approaches. ROXy is a toy implementation of two schemes described by Ran Canetti et. al. in [this paper](https://link.springer.com/content/pdf/10.1007/BFb0052229.pdf), including a symmetric scheme and an asymmetric scheme. 
While not exactly as specified due to a lack of access to entropy-measuring instruments for true RNG, this toy demonstrates the capabilities and possibilities of these forms of cryptography, as well as showcases the mathematical and logical background for these schemes.

## Describing the Schemes
### Symmetric
One of the symmetric schemes offered by Dr. Canetti and his peers is shockingly basic, yet effective, and returns to an old but proven concept in cryptography, that being the One-Time Pad (OTP). Utilizing the well-known self-inverting (involution) property of XOR along with the security of the OTP, they
propose a simple scheme described as follows:

Given a cleartext $m$ and a key $k_{1}$, such that $|m| = |k_{1}|$, perform a bitwise XOR operation to yield a ciphertext $c$ such that $c = m \bigoplus k_{1}$. Prepare a chosen decoy cleartext $d$, such that $|d| = |m|$. From this, perform $c \bigoplus d$ to derive $k_{2}$, which will serve
to decrypt the ciphertext into our chosen decoy.

Naturally, this is not a practical system in contemporary times, as any other OTP is also not practical. However, it serves an interesting purpose to illustrate the concept and power of deniable cryptography to motivate further study.

### Asymmetric
Additionally, Canetti and his coauthors offer multiple asymmetric schemes in their paper, although sufficiently more complex than the basic symmetric scheme. All described schemes are reliant on the construction of a set of finite length bitstrings he dubs Translucent sets, which postulate an encryption function $F$, 
a hardcore predicate function $B$, and a trapdoor permutation $D$ for inversion. The construction employed by ROXy is the second, defined as follows:


- Let $t : s + k$.
- Represent each $x \in \\{0, 1\\}^{t}$ as $x = x_{0}, b_{1},...,b_{k}$, where $x_{0} \in \\{0,1\\}^{s}$ and for $i \geq 1$ each $b_{i} \in \\{0, 1\\}$.
- Then let $S_{t} = \\{x_{0}, b_{1},...b_{k} \in \\{0, 1\\}^{s+k} | \forall i = 1...k, B(f^{-i}(x_{0})) = b_{i}\\}$.

To further elaborate, we find $s$ to be the original length of the arbitrary bitstring $x_{0}$, and $k$ to be the length of the bitstring generated by the $k$ rounds of encryption and the application of the hardcore predicate $B$ on that round's value of $x_{0}$, yielding a $t$ length bitstring. 


Having constructed the translucent set, we then construct a *sender deniable* asymmetric scheme involving them. For implementation, ROXy uses textbook RSA as our encryption function $F$, retaining the generating primes $p, q$ for the trapdoor permutation $D$.
The hardcore predicate $B$ in use is simply a bitstring length iterative sum over GF2. This is sufficient information for the sender to generate elements of $S_{t}$.
To encode a 1, the sender will send an element of $S_{t}$, and to encode a 0, they will send a $t$ length randomly generated bitstring, either by an alternative CSPRNG algorithm or TRNG via additional hardware. The recipient, able to use the trapdoor permutation $D$ to invert the encryption, will thus be 
able to determine if a sent element is or is not in $S_{t}$. As such, they will always correctly decrypt a 1, however, there is a small chance that they will incorrectly decrypt a 0 (specifically, $2^{-k}$). This is insufficient for the scheme to provide recipient deniability, however, it is sender deniable,
as the sender can claim that any sent element was randomly generated or pseudorandomly generated, allowing for any combination of $t$ bits to be the possible cleartext. 

## Conclusion
While both schemes are inefficient, they do provide the desirable characteristic of deniability. Additional schemes proposed by the authors in the same paper provide some different characteristics, such as a scheme allowing for the additional requirement of recipient deniability, and a symmetric scheme in which multiple additional
keys are made available for even more selective faking. We also see alternative constructions and a more in depth analysis of the proposed schemes. However, while applications of these schemes may seem limited, they may have interesting applications in malware crypting and obfuscation, along with maintenance of stealth. They also
provide a base for further study such that efficient systems may arise, as this is very much a desirable quality in encryption.

## Thanks
Thank you to the Cryptography for Everybody Discord server, specifically user codewarrior0, for helping to interpret part of the original paper in the context of application. 

## Further Reading and References
 - [Canetti, Ran et. al. - Deniable Encryption](https://link.springer.com/content/pdf/10.1007/BFb0052229.pdf)
 - [Wikipedia - Deniable Encryption](https://en.wikipedia.org/wiki/Deniable_encryption)
 - [Wikipedia - Hidden Volumes](https://en.wikipedia.org/wiki/Disk_encryption_software#Hidden_volumes)
