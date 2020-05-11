---
title: Limits on AEAD Algorithms
abbrev: AEAD Limits
docname: draft-thomson-cfrg-aead-limits-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: M. Thomson
    name: Martin Thomson
    org: Mozilla
    email: mt@lowentropy.net
 -  ins: C. A. Wood
    name: Christopher A. Wood
    org: Cloudflare
    email: caw@heapingbits.net

normative:
  GCM:
    title: "Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM) and GMAC"
    date: 2007-11
    author:
      - ins: M. Dworkin
    seriesinfo:
      NIST: Special Publication 800-38D

informative:
  NonceDisrespecting:
    target: https://eprint.iacr.org/2016/475.pdf
    title: Nonce-Disrespecting Adversaries -- Practical Forgery Attacks on GCM in TLS
    author:
      -
        ins: H. Bock
      -
        ins: A. Zauner
      -
        ins: S. Devlin
      -
        ins: J. Somorovsky
      -
        ins: P. Jovanovic
    date: 2016-05-17
  Poly1305:
    title: "The Poly1305-AES message-authentication code"
    target: https://link.springer.com/content/pdf/10.1007/11502760_3.pdf
    author:
      - ins: D. J. Bernstein
    seriesinfo: "International Workshop on Fast Software Encryption, 2005"
  ChaCha20Poly1305Bounds:
    title: "A Security Analysis of the Composition of ChaCha20 and Poly1305"
    author:
      - ins: G. Procter
    date: 2014
    target: https://eprint.iacr.org/2014/613.pdf
  AEBounds:
    title: "Limits on Authenticated Encryption Use in TLS"
    author:
      - ins: A. Luykx
      - ins: K. Paterson
    date: 2016-03-08
    target: http://www.isg.rhul.ac.uk/~kp/TLS-AEbounds.pdf

--- abstract

TODO

--- middle

# Introduction

Authenticated Encryption with Associated Data (AEAD) is an encryption algorithm
that provides confidentiality and integrity. {{!RFC5116}} specifies an AEAD
encryption algorithm as a function with four inputs -- secret key, nonce, plaintext,
and optional associated data -- that produces ciphertext output and error code
indicating success of failure. The ciphertext is typically composed of the encrypted
plaintext bytes and an authentication tag.

Use of this interface is left unspecified. In particular, the interface imposes no
maximum length on the nonce, plaintext, ciphertext, or additional data. Moreover,
requirements for different inputs, such as the nonce, are left unspecified.
Some AEAD algorithms, however, have differing limits and usage requirements.
For example, some algorithms limit the number of bytes that one can encrypt and
decrypt per key, or per key and nonce pair, without compromising the algorithm's
confidentiality or integrity properties. Some AEAD algorithms also require that a
key and nonce never be re-used across encryptions.

In practice, the limits and requirements of AEAD algorithms have been violated,
leading to known security vulnerabilities. For example, nonce reuse with AES-GCM
can have disastrous consequences on data privacy and integrity. See {{NonceDisrespecting}}
for an example of these attacks. TLS 1.3 limits the amount of (fixed-size) plaintext
records can encrypt without compromising the confidentiality and integrity bounds
of AES-GCM. See {{?RFC8446}}, Section 5.5.

Currently, AEAD limits and usage requirements are scattered among peer-reviewed papers,
standards documents, and other RFCs. The intent of this document is to collate all
relevant information about the proper usage and limits of AEAD algorithms in one place.
This may serve as a standard reference when considering which AEAD algorithm to use,
and how to use it.

# Requirements Notation

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in
BCP14 {{!RFC2119}} {{!RFC8174}}  when, and only when, they appear in
all capitals, as shown here.

# Notation

This document defines limitations in part using the quantities below.

| Symbol  | Description |
| n | Size of the AEAD block cipehr (in bits)|
| t | Size of the authentication tag (in bits) |
| l | Number of 16-byte blocks in a message |
| s | Total plaintext length in blocks |
| q | Number of encryption attempts |
| v | Number of forgery attempts |
| p | Adversary attack probability |

For each AEAD algorithm, we define the confidentiality and integrity advantage
roughly as the advantage an attacker has in breaking the corresponding security
property for the algorithm. Specifically:

- Confidentiality advantage (CA): The advantage of an attacker succeeding in breaking
the confidentiality properties of the AEAD, i.e., by gaining an advantage in
distinguishing the AEAD instance from an ideal pseudorandom permutation (PRP).
- Integrity advantage (IA): The probability of an attacker succeeding in breaking
the integrity properties of the AEAD, i.e., by producing a forgery.

Given a quantifiable advantage, we then compute limits on the AEAD algorithm,
as a function of the algorithm's input parameters. This document defines two limits:

- Confidentiality limit (CL): The limit of *plaintext blocks* an application can
encrypt before given the adversary a non-negligible advantage.
- Integrity limit (IL): The limit of *ciphertext blocks* an application can process,
either successfully or not, before giving the adversary a non-negligible advantage.

Advantages are expressed as equations in terms of the message size l, total number
of plaintext blocks processed s, encryption attempts q, and forgery attempts v.
Limits are then derived from those bounds using a target attacker probability.
For example, given an advantage of q\*v and attacker success probability of p,
the algorithm remains secure with respect provided that q\*v <= p. In turn, this
implies that v <= p/q is the corresponding limit.

# AEAD Limits and Requirements {#limits}

This section summarizes the confidentiality and integrity bounds and limits for modern AEAD algorithms
used in IETF protocols, including: AEAD_AES_128_GCM {{!RFC5116}}, AEAD_AES_256_GCM {{!RFC5116}},
AEAD_AES_128_CCM {{!RFC5116}}, AEAD_CHACHA20_POLY1305 {{!RFC7539}}, AEAD_AES_128_CCM_8 {{!RFC6655}}.

The CL and IL values bound the total number of encryption and forgery queries (q and v).
Alongside each value, we also specify these bounds.

## AEAD_AES_128_GCM and AEAD_AES_256_GCM

The CL and IL values for AES-GCM are derived in {{AEBounds}} and summarized below.

### Confidentiality Limit

~~~
CA = ((s + q + 1)^2) / 2^127
~~~

This implies the following limit:

~~~
q <= sqrt(p * 2^127) - s - 1
~~~

### Integrity Limit

~~~
IA = 2 * (v * (l + 1)) / 2^128
~~~

This implies the following limit:

~~~
v <= (p * 2^127) / (l + 1)
~~~

## AEAD_CHACHA20_POLY1305

The only known analysis for AEAD_CHACHA20_POLY1305 {{ChaCha20Poly1305Bounds}}
combines the confidentiality and integrity limits into a single expression,
covered below:

~~~
v * (8l / 2^106)
~~~

This advantage is a tight reduction based on the underlying Poly1305 PRF {{Poly1305}}.
It implies the following limit:

~~~
v <= (p * 2^106) / 8l
~~~

## AEAD_AES_128_CCM

The CL and IL values for AEAD_AES_128_CCM are derived from {{?CCM-ANALYSIS=DOI.10.1007/3-540-36492-7_7}}
and specified in the QUIC-TLS mapping specification {{?I-D.ietf-quic-tls}}.

### Confidentiality Limit

~~~
CA: (2l * q)^2 / 2^128
~~~

This implies the following limit:

~~~
q <= sqrt((p * (2^127)) / l^2)
~~~

### Integrity Limit

~~~
IA: v / 2^t + (2l * (v + q))^2 / 2^n
~~~

This implies the following limit:

~~~
TODO(caw)
~~~

## AEAD_AES_128_CCM_8

TODO

# Security Considerations {#sec-considerations}

TODO

# IANA Considerations

This document does not make any IANA requests.

--- back
