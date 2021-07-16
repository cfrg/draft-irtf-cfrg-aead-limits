---
title: Usage Limits on AEAD Algorithms
abbrev: AEAD Limits
docname: draft-irtf-cfrg-aead-limits-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: F. Günther
    name: Felix Günther
    org: ETH Zurich
    email: mail@felixguenther.info
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
  GCMProofs:
    title: "Breaking and Repairing GCM Security Proofs"
    target: https://eprint.iacr.org/2012/438.pdf
    date: 2012-08-01
    author:
      - ins: T. Iwata
      - ins: K. Ohashi
      - ins: K. Minematsu
  ChaCha20Poly1305Bounds:
    title: "A Security Analysis of the Composition of ChaCha20 and Poly1305"
    author:
      - ins: G. Procter
    date: 2014-08-11
    target: https://eprint.iacr.org/2014/613.pdf
  AEBounds:
    title: "Limits on Authenticated Encryption Use in TLS"
    author:
      - ins: A. Luykx
      - ins: K. Paterson
    date: 2016-03-08
    target: http://www.isg.rhul.ac.uk/~kp/TLS-AEbounds.pdf
  AEComposition:
    title: "Authenticated Encryption: Relations among notions and analysis of the generic composition paradigm"
    author:
      - ins: M. Bellare
      - ins: C. Namprempre
    date: 2007-07
    target: http://cseweb.ucsd.edu/~mihir/papers/oem.pdf
  AEAD:
    title: "Authenticated-Encryption with Associated-Data"
    author:
      - ins: P. Rogaway
    date: 2002-09
    target: https://cseweb.ucsd.edu/~mihir/papers/musu.pdf
  MUSecurity:
    title: "Public-Key Encryption in a Multi-user Setting: Security Proofs and Improvements"
    author:
      - ins: M. Bellare
      - ins: A. Boldyreva
      - ins: S. Micali
    date: 2000-05
    target: https://cseweb.ucsd.edu/~mihir/papers/musu.pdf
  GCM-MU:
    title: "The Multi-User Security of Authenticated Encryption: AES-GCM in TLS 1.3"
    target: https://eprint.iacr.org/2016/564.pdf
    date: 2017-11-27
    author:
      - ins: M. Bellare
      - ins: B. Tackmann
  GCM-MU2:
    title: "The Multi-user Security of GCM, Revisited: Tight Bounds for Nonce Randomization"
    target: https://eprint.iacr.org/2018/993.pdf
    date: 2018-10-15
    author:
      - ins: V. T. Hoang
      - ins: S. Tessaro
      - ins: A. Thiruvengadam


informative:
  NonceDisrespecting:
    target: https://eprint.iacr.org/2016/475.pdf
    title: "Nonce-Disrespecting Adversaries -- Practical Forgery Attacks on GCM in TLS"
    author:
      - ins: H. Bock
      - ins: A. Zauner
      - ins: S. Devlin
      - ins: J. Somorovsky
      - ins: P. Jovanovic
    date: 2016-05-17
  MF05:
    title: Multiple forgery attacks against Message Authentication Codes
    target: https://csrc.nist.gov/CSRC/media/Projects/Block-Cipher-Techniques/documents/BCM/Comments/CWC-GCM/multi-forge-01.pdf
    author:
      - ins: D. A. McGrew
      - ins: S. R. Fluhrer
    date: 2005-05-31
  TLS: RFC8446

--- abstract

An Authenticated Encryption with Associated Data (AEAD) algorithm provides
confidentiality and integrity.  Excessive use of the same key can give an
attacker advantages in breaking these properties.  This document provides simple
guidance for users of common AEAD functions about how to limit the use of keys
in order to bound the advantage given to an attacker.  It considers limits in
both single- and multi-key settings.

--- middle

# Introduction

An Authenticated Encryption with Associated Data (AEAD) algorithm
provides confidentiality and integrity. {{!RFC5116}} specifies an AEAD
as a function with four inputs -- secret key, nonce, plaintext, associated data
(of which plaintext and associated data can optionally be zero-length) -- that
produces ciphertext output and an error code
indicating success or failure. The ciphertext is typically composed of the encrypted
plaintext bytes and an authentication tag.

The generic AEAD interface does not describe usage limits.  Each AEAD algorithm
does describe limits on its inputs, but these are formulated as strict
functional limits, such as the maximum length of inputs, which are determined by
the properties of the underlying AEAD composition.  Degradation of the security
of the AEAD as a single key is used multiple times is not given the same
thorough treatment.

Effective limits can be influenced by the number of "users" of
a given key. In the traditional setting, there is one key shared between two
parties. Any limits on the maximum length of inputs or encryption operations
apply to that single key. The attacker's goal is to break security
(confidentiality or integrity) of that specific key. However, in practice, there
are often many users with independent keys. This multi-key security setting,
often referred to as the multi-user setting in the academic literature,
considers an attacker's advantage in breaking security of any of these many
keys, further assuming the attacker may have done some offline work to help break
security. As a result, AEAD algorithm limits may depend on offline work and the
number of keys. However, given that a multi-key attacker does not target any specific
key, acceptable advantages may differ from that of the single-key setting.

The number of times a single pair of key and nonce can be used might also be
relevant to security.  For some algorithms, such as AEAD_AES_128_GCM or
AEAD_AES_256_GCM, this limit is 1 and using the same pair of key and nonce has
serious consequences for both confidentiality and integrity; see
{{NonceDisrespecting}}.  Nonce-reuse resistant algorithms like
AEAD_AES_128_GCM_SIV can tolerate a limited amount of nonce reuse.

It is good practice to have limits on how many times the same key (or pair of
key and nonce) are used.  Setting a limit based on some measurable property of
the usage, such as number of protected messages or amount of data transferred,
ensures that it is easy to apply limits.  This might require the application of
simplifying assumptions.  For example, TLS 1.3 and QUIC both specify limits on
the number of records that can be protected, using the simplifying assumption
that records are the same size; see {{Section 5.5 of TLS}} and {{Section 6.6 of
RFC9001}}.

Exceeding the determined usage limit can be avoided using rekeying.  Rekeying
uses a lightweight transform to produce new keys.  Rekeying effectively resets
progress toward single-key limits, allowing a session to be extended without
degrading security.  Rekeying can also provide a measure of post-compromise
security.  {{?RFC8645}} contains a thorough survey of rekeying and the
consequences of different design choices.

Currently, AEAD limits and usage requirements are scattered among peer-reviewed
papers, standards documents, and other RFCs. Determining the correct limits for
a given setting is challenging as papers do not use consistent labels or
conventions, and rarely apply any simplifications that might aid in reaching a
simple limit.

The intent of this document is to collate all relevant information about the
proper usage and limits of AEAD algorithms in one place.  This may serve as a
standard reference when considering which AEAD algorithm to use, and how to use
it.

# Requirements Notation

{::boilerplate bcp14}

# Notation

This document defines limitations in part using the quantities below.

| Symbol  | Description |
|-:-|:-|
| n | AEAD block length (in bits) |
| k | AEAD key length (in bits) |
| r | AEAD nonce length (in bits) |
| t | Size of the authentication tag (in bits) |
| l | Maximum length of each message (in blocks) |
| s | Total plaintext length in all messages (in blocks) |
| q | Number of protected messages (AEAD encryption invocations) |
| v | Number of attacker forgery attempts (failed AEAD decryption invocations) |
| p | Upper bound on adversary attack probability |
| o | Offline adversary work (in number of encryption and decryption queries; multi-key setting only) |
| u | Number of keys (multi-key setting only) |
| B | Maximum number of blocks encrypted by any key (multi-key setting only) |

For each AEAD algorithm, we define the (passive) confidentiality and (active)
integrity advantage roughly as the advantage an attacker has in breaking the
corresponding classical security property for the algorithm. A passive attacker
can query ciphertexts for arbitrary plaintexts. An active attacker can additionally
query plaintexts for arbitrary ciphertexts. Moreover, we define the combined
authenticated encryption advantage guaranteeing both confidentiality and integrity
against an active attacker. Specifically:

- Confidentiality advantage (CA): The probability of a passive attacker
succeeding in breaking the confidentiality properties (IND-CPA) of the AEAD scheme.
In this document, the definition of confidentiality advantage roughly is the
probability that an attacker successfully distinguishes the ciphertext outputs
of the AEAD scheme from the outputs of a random function.

- Integrity advantage (IA): The probability of a active attacker succeeding
in breaking the integrity properties (INT-CTXT) of the AEAD scheme. In this document,
the definition of integrity advantage roughly is the probability that an attacker
is able to forge a ciphertext that will be accepted as valid.

- Authenticated Encryption advantage (AEA): The probability of a active
attacker succeeding in breaking the authenticated-encryption properties of the
AEAD scheme. In this document, the definition of authenticated encryption
advantage roughly is the probability that an attacker successfully distinguishes
the ciphertext outputs of the AEAD scheme from the outputs of a random function
or is able to forge a ciphertext that will be accepted as valid.

See {{AEComposition}}, {{AEAD}} for the formal definitions of and relations
between passive confidentiality (IND-CPA), ciphertext integrity (INT-CTXT),
and authenticated encryption security (AE).
The authenticated encryption advantage subsumes, and can be derived as the
combination of, both CA and IA:

~~~
CA <= AEA
IA <= AEA
AEA <= CA + IA
~~~

Each application requires an individual determination of limits in order to keep CA
and IA sufficiently small.  For instance, TLS aims to keep CA below 2<sup>-60</sup> and IA
below 2<sup>-57</sup> in the single-key setting; see {{Section 5.5 of TLS}}.

# Calculating Limits

Once upper bounds on CA, IA, or AEA are determined, this document
defines a process for determining three overall operational limits:

- Confidentiality limit (CL): The number of messages an application can encrypt
  before giving the adversary a confidentiality advantage higher than CA.

- Integrity limit (IL): The number ciphertexts an application can decrypt,
  either successfully or not, before giving the adversary an integrity advantage
  higher than IA.

- Authenticated encryption limit (AEL): The combined number of messages and
  number of ciphertexts an application can encrypt or decrypt before giving the
  adversary an authenticated encryption advantage higher than AEA.

When limits are expressed as a number of messages an application can encrypt or
decrypt, this requires assumptions about the size of messages and any
authenticated additional data (AAD).  Limits can instead be expressed in terms
of the number of bytes, or blocks, of plaintext and maybe AAD in total.

To aid in translating between message-based and byte/block-based limits,
a formulation of limits that includes a maximum message size (l) and the AEAD
schemes' block length in bits (n) is provided.

All limits are based on the total number of messages, either the number of
protected messages (q) or the number of forgery attempts (v); which correspond
to CL and IL respectively.

Limits are then derived from those bounds using a target attacker probability.
For example, given an integrity advantage of `IA = v * (8l / 2^106)` and a
targeted maximum attacker success probability of `IA = p`, the algorithm remains
secure, i.e., the adversary's advantage does not exceed the targeted probability
of success, provided that `v <= (p * 2^106) / 8l`. In turn, this implies that
`v <= (p * 2^103) / l` is the corresponding limit.

To apply these limits, implementations can count the number of messages that are
protected or rejected against the determined limits (q and v respectively).
This requires that messages cannot exceed the maximum message size (l) that is
chosen.

This analysis assumes a message-based approach to setting limits.
Implementations that use byte counting rather than message counting could use a
maximum message size (l) of one to determine a limit for q that can be applied
with byte counting.  This results in attributing per-message overheads to every
byte, so the resulting limit could be significantly lower than necessary.
Actions, like rekeying, that are taken to avoid the limit might occur more
often as a result.


# Single-Key AEAD Limits {#su-limits}

This section summarizes the confidentiality and integrity bounds and limits for modern AEAD algorithms
used in IETF protocols, including: AEAD_AES_128_GCM {{!RFC5116}}, AEAD_AES_256_GCM {{!RFC5116}},
AEAD_AES_128_CCM {{!RFC5116}}, AEAD_CHACHA20_POLY1305 {{!RFC8439}}, AEAD_AES_128_CCM_8 {{!RFC6655}}.

The CL and IL values bound the total number of encryption and forgery queries (q and v).
Alongside each value, we also specify these bounds.

## AEAD_AES_128_GCM and AEAD_AES_256_GCM

The CL and IL values for AES-GCM are derived in {{AEBounds}} and summarized below.
For this AEAD, n = 128 and t = 128 {{GCM}}. In this example, the length s is the sum
of AAD and plaintext, as described in {{GCMProofs}}.

### Confidentiality Limit

~~~
CA <= ((s + q + 1)^2) / 2^129
~~~

This implies the following usage limit:

~~~
q + s <= p^(1/2) * 2^(129/2) - 1
~~~

Which, for a message-based protocol with `s <= q * l`, if we assume that every
packet is size `l`, produces the limit:

~~~
q <= (p^(1/2) * 2^(129/2) - 1) / (l + 1)
~~~

### Integrity Limit

~~~
IA <= 2 * (v * (l + 1)) / 2^128
~~~

This implies the following limit:

~~~
v <= (p * 2^127) / (l + 1)
~~~

## AEAD_CHACHA20_POLY1305

The only known analysis for AEAD_CHACHA20_POLY1305 {{ChaCha20Poly1305Bounds}}
combines the confidentiality and integrity limits into a single expression,
covered below:

<!-- I've got to say that this is a pretty unsatisfactory situation. -->

~~~
CA <= v * ((8 * l) / 2^106)
IA <= v * ((8 * l) / 2^106)
~~~

This advantage is a tight reduction based on the underlying Poly1305 PRF {{!Poly1305=DOI.10.1007/11502760_3}}.
It implies the following limit:

~~~
v <= (p * 2^103) / l
~~~

## AEAD_AES_128_CCM

The CL and IL values for AEAD_AES_128_CCM are derived from {{!CCM-ANALYSIS=DOI.10.1007/3-540-36492-7_7}}
and specified in the QUIC-TLS mapping specification {{?I-D.ietf-quic-tls}}. This analysis uses the total
number of underlying block cipher operations to derive its bound. For CCM, this number is the sum of:
the length of the associated data in blocks, the length of the ciphertext in blocks, the length of
the plaintext in blocks, plus 1.

In the following limits, this is simplified to a value of twice the length of the packet in blocks,
i.e., 2l represents the effective length, in number of block cipher operations, of a message with
l blocks. This simplification is based on the observation that common applications of this AEAD carry
only a small amount of associated data compared to ciphertext. For example, QUIC has 1 to 3 blocks of AAD.

For this AEAD, n = 128 and t = 128.

### Confidentiality Limit

~~~
CA <= (2l * q)^2 / 2^n
   <= (2l * q)^2 / 2^128
~~~

This implies the following limit:

~~~
q <= sqrt((p * 2^126) / l^2)
~~~

### Integrity Limit

~~~
IA <= v / 2^t + (2l * (v + q))^2 / 2^n
   <= v / 2^128 + (2l * (v + q))^2 / 2^128
~~~

This implies the following limit:

~~~
v + (2l * (v + q))^2 <= p * 2^128
~~~

In a setting where `v` or `q` is sufficiently large, `v` is negligible compared to
`(2l * (v + q))^2`, so this this can be simplified to:

~~~
v + q <= p^(1/2) * 2^63 / l
~~~

## AEAD_AES_128_CCM_8

The analysis in {{!CCM-ANALYSIS}} also applies to this AEAD, but the reduced tag
length of 64 bits changes the integrity limit calculation considerably.

~~~
IA <= v / 2^t + (2l * (v + q))^2 / 2^n
   <= v / 2^64 + (2l * (v + q))^2 / 2^128
~~~

This results in reducing the limit on `v` by a factor of 2^64.

~~~
v * 2^64 + (2l * (v + q))^2 <= p * 2^128
~~~


## Single-Key Examples

An example protocol might choose to aim for a single-key CA and IA that is at
most 2<sup>-50</sup>.  If the messages exchanged in the protocol are at most a
common Internet MTU of around 1500 bytes, then a value for l might be set to
2<sup>7</sup>.  The values in {{ex-table}} show values of q and v that might be
chosen under these conditions.

| AEAD                   | Maximum q        | Maximum v      |
|:-----------------------|-----------------:|---------------:|
| AEAD_AES_128_GCM       | 2<sup>32.5</sup> | 2<sup>71</sup> |
| AEAD_AES_256_GCM       | 2<sup>32.5</sup> | 2<sup>71</sup> |
| AEAD_CHACHA20_POLY1305 | n/a              | 2<sup>46</sup> |
| AEAD_AES_128_CCM       | 2<sup>30</sup>   | 2<sup>30</sup> |
| AEAD_AES_128_CCM_8     | 2<sup>30.9</sup> | 2<sup>13</sup> |
{: #ex-table title="Example limits"}

AEAD_CHACHA20_POLY1305 provides no limit to q based on the provided analysis.

The limit for q on AEAD_AES_128_CCM and AEAD_AES_128_CCM_8 is reduced due to a
need to reduce the value of q to ensure that IA does not exceed the target.
This assumes equal proportions for q and v for AEAD_AES_128_CCM.
AEAD_AES_128_CCM_8 in permits a much smaller value of v due to the shorter tag,
which permits a higher limit for q.

Some protocols naturally limit v to 1, such as TCP-based variants of TLS, which
terminate sessions on decryption failure.  If v is limited to 1, q can be
increased to 2<sup>31</sup> for both CCM AEADs.



# Multi-Key AEAD Limits {#mu-limits}

In the multi-key setting, each user is assumed to have an independent and
identically distributed key, though nonces may be re-used across users with some
very small probability. The success probability in attacking one of these many
independent keys can be generically bounded by the success probability of
attacking a single key multiplied by the number of keys present {{MUSecurity}}, {{GCM-MU}}.
Absent concrete multi-key bounds, this means the attacker advantage in the multi-key
setting is the product of the single-key advantage and the number of keys.

This section summarizes the confidentiality and integrity bounds and limits for
the same algorithms as in {{su-limits}} for the multi-key setting. The CL
and IL values bound the total number of encryption and forgery queries (q and v).
Alongside each value, we also specify these bounds.

## AEAD_AES_128_GCM and AEAD_AES_256_GCM

Concrete multi-key bounds for AEAD_AES_128_GCM and AEAD_AES_256_GCM exist due to
Theorem 4.3 in {{GCM-MU2}}, which covers protocols with nonce randomization,
like TLS 1.3 {{TLS}} and QUIC {{?RFC9001}}.

Results for AES-GCM without nonce randomization are captured by Theorem 3.1 in
{{GCM-MU2}}, which apply to protocols such as TLS 1.2 {{?RFC5246}}.  This
produces similar limits under most conditions.

For this AEAD, n = 128, t = 128, and r = 96; the key length is k = 128 or k =
256 for AEAD_AES_128_GCM and AEAD_AES_128_GCM respectively.


### Authenticated Encryption Security Limit {#mu-gcm-ae}

<!--
    From {{GCM-MU2}} Theorem 4.3.

    Let:
        - #blocks encrypted/verified overall:   \sigma = (q + v) * l
        - worst-case  o (offline work), q+v, \sigma <= 2^95
          (Theorem 4.3 requires q <= 2^(1-e)r ; this yields e >= 0.0104, hence
          d = 1,5/e -1 <= 143 <= 2^8.)

    We can simplify as follows:
        - Note: Last term is 2^-48; hence any other term <= 2^-50 is negligible.
        - 1st term (../2^k):  roughly <= 2^8 * (o + q+v + \sigma) / 2^k
           roughly <= (o + (q+v)*l) / 2^(k-8)
          This is negligible for k = 256.
          For k = 128, it is negligible if o, (q+v)*l <= 2^70.
          For o <= 2^70 and B >= 2^8, it is dominated by the 2nd term;
            we assume that and hence omit the 1st term.
          If B is small and k = 128, then \sigma might be relevant and
            we can add n*\sigma/2^128
        - 2nd term (../2^n):
          \sigma*(2B + cn + 2) = \sigma*(B + 97)/2^127 in Theorem 4.3
          \sigma*(2B + cn + 3) = \sigma*(B + 97.5)/2^127 in Theorem 3.1
          assuming that B >> 100, the dominant term is \sigma*B/2^127
        - 3rd term (../2^2n):  <= 2^-160, negligible.
        - 4th term (../2^(k+n)):  roughly <= (\sigma^2 + 2o(q+v)) / 2^256
          <= 2^-64, negligible.
        - 5th term (2^(-r/2)):  = 2^48
-->
Protocols with nonce randomization have a limit of:

~~~
AEA <= ((q+v)*l*B / 2^127) + (1 / 2^48)
~~~

This implies the following limit:

~~~
q + v <= (p * 2^127 - 2^79) / (l * B)
~~~

This assumes that B is much larger than 100; that is, each user enciphers
significantly more than 1600 bytes of data.  Otherwise, B should be increased by 161 for
AEAD_AES_128_GCM and by 97 for AEAD_AES_256_GCM.

Protocols without nonce randomization have limits that are essentially the
same provided that p is not less than 2<sup>-48</sup>, as the simplified
expression for AEA does not include the 2<sup>-48</sup> term:

~~~
q + v <= p * 2^127 / (l * B)
~~~

Without nonce randomization, B should be increased by an additional 0.5.


### Confidentiality Limit

<!--
    From {{GCM-MU2}} Theorem 4.3,
    substracting terms for Pr[Bad_7] and Pr[Bad_8],
    and applying simplifications as above (note there are no verification queries),
    we obtain:

    Adv^{mu-ae w/o INT}_RCAU <=
        2^8 * (o + q) / 2^k   +  \sigma*B/2^127  +  2^48

    For o <= 2^70 and any B, the 1st term is dominated by the 2nd term;
    we assume that and hence again omit the 1st term.
-->

The confidentiality advantage is essentially dominated by the same terms as
the AE advantage for protocols with nonce randomization:

~~~
CA <= (q*l*B / 2^127) + (1 / 2^48)
~~~

This implies the following limit:

~~~
q <= (p * 2^127 - 2^79) / (l * B)
~~~

As before, the limit without nonce randomization is:

~~~
q <= (p * 2^127) / (l * B)
~~~


### Integrity Limit

There is currently no dedicated integrity multi-key bound available for
AEAD_AES_128_GCM and AEAD_AES_256_GCM. The AE limit can be used to derive
an integrity limit as:

~~~
IA <= AEA
~~~

{{mu-gcm-ae}} therefore contains the integrity limits.


## AEAD_CHACHA20_POLY1305, AEAD_AES_128_CCM, and AEAD_AES_128_CCM_8

There are currently no concrete multi-key bounds for AEAD_CHACHA20_POLY1305,
AEAD_AES_128_CCM, or AEAD_AES_128_CCM_8. Thus, to account for the additional
factor `u`, i.e., the number of keys, each `p` term in the confidentiality and
integrity limits is replaced with `p / u`.

### AEAD_CHACHA20_POLY1305

The combined confidentiality and integrity limit for AEAD_CHACHA20_POLY1305 is
as follows.

~~~
v <= ((p / u) * 2^106) / 8l
  <= (p * 2^103) / (l * u)
~~~

### AEAD_AES_128_CCM and AEAD_AES_128_CCM_8

The integrity limit for AEAD_AES_128_CCM is as follows.

~~~
v + q <= (p / u)^(1/2) * 2^63 / l
~~~

Likewise, the integrity limit for AEAD_AES_128_CCM_8 is as follows.

~~~
v * 2^64 + (2l * (v + q))^2 <= (p / u) * 2^128
~~~

# Security Considerations {#sec-considerations}

The different analyses of AEAD functions that this work is based upon generally
assume that the underlying primitives are ideal.  For example, that the
pseudorandom function (PRF) or pseudorandom permutation (PRP) the AEAD builds
upon is indistinguishable from a truly random function.  Thus, the advantage
estimates assume that the attacker is not able to exploit a weakness in an
underlying primitive.

Many of the formulae in this document depend on simplifying assumptions,
from differing models, which means that results are not universally applicable. When using this
document to set limits, it is necessary to validate all these assumptions
for the setting in which the limits might apply. In most cases, the goal is
to use assumptions that result in setting a more conservative limit, but this
is not always the case. As an example of one such simplification, this document
defines v as the total number of failed decryption queries (that is, failed forgery
attempts), whereas models usually count in v all forgery attempts.

The CA and IA values defined in this document are upper bounds based on existing
cryptographic research. Future analysis may introduce tighter bounds. Applications
SHOULD NOT assume these bounds are rigid, and SHOULD accommodate changes. In
particular, in two-party communication, one participant cannot regard apparent
overuse of a key by other participants as being in error, when it could be that
the other participant has better information about bounds.

Note that the limits in this document apply to the adversary's ability to
conduct a single successful forgery. For some algorithms and in some cases,
an adversary's success probability in repeating forgeries may be noticeably
larger than that of the first forgery. As an example, {{MF05}} describes
such multiple forgery attacks in the context of AES-GCM in more detail.

# IANA Considerations

This document does not make any request of IANA.

--- back
