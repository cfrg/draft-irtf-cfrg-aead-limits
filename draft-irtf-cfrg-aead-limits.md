---
title: Usage Limits on AEAD Algorithms
abbrev: AEAD Limits
docname: draft-irtf-cfrg-aead-limits-latest
category: info
stream: IRTF

v: 3
keyword:
  - safe
  - limits
  - crypto

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
  ChaCha20Poly1305-SU:
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
    target: https://eprint.iacr.org/2000/025.pdf
  AEAD:
    title: "Authenticated-Encryption with Associated-Data"
    author:
      - ins: P. Rogaway
    date: 2002-09
    target: https://web.cs.ucdavis.edu/~rogaway/papers/ad.pdf
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
  ChaCha20Poly1305-MU:
    title: "The Security of ChaCha20-Poly1305 in the Multi-user Setting"
    target: https://eprint.iacr.org/2023/085.pdf
    date: 2023-01-24
    author:
      - ins: J. P. Degabriele
      - ins: J. Govinden
      - ins: F. Günther
      - ins: K. G. Paterson


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
degrading security.  Rekeying can also provide a measure of forward and
backward (post-compromise) security.  {{?RFC8645}} contains a thorough survey
of rekeying and the consequences of different design choices.

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

This document defines limitations in part using the quantities in
{{notation-table}} below.

| Symbol  | Description |
|-:-|:-|
| n | AEAD block length (in bits) |
| k | AEAD key length (in bits) |
| r | AEAD nonce length (in bits) |
| t | Size of the authentication tag (in bits) |
| L | Maximum length of each message (in blocks) |
| s | Total plaintext length in all messages (in blocks) |
| q | Number of protected messages (AEAD encryption invocations) |
| v | Number of attacker forgery attempts (failed AEAD decryption invocations) |
| p | Upper bound on adversary attack probability |
| o | Offline adversary work (in number of encryption and decryption queries; multi-key setting only) |
| u | Number of keys (multi-key setting only) |
| B | Maximum number of blocks encrypted by any key (multi-key setting only) |
{: #notation-table title="Notation"}

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

- Integrity advantage (IA): The probability of an active attacker succeeding
in breaking the integrity properties (INT-CTXT) of the AEAD scheme. In this document,
the definition of integrity advantage roughly is the probability that an attacker
is able to forge a ciphertext that will be accepted as valid.

- Authenticated Encryption advantage (AEA): The probability of an active
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
a formulation of limits that includes a maximum message size (`L`) and the AEAD
schemes' block length in bits (`n`) is provided.

All limits are based on the total number of messages, either the number of
protected messages (`q`) or the number of forgery attempts (`v`); which correspond
to CL and IL respectively.

Limits are then derived from those bounds using a target attacker probability.
For example, given an integrity advantage of `IA = v * (8L / 2^106)` and a
targeted maximum attacker success probability of `IA = p`, the algorithm remains
secure, i.e., the adversary's advantage does not exceed the targeted probability
of success, provided that `v <= (p * 2^106) / 8L`. In turn, this implies that
`v <= (p * 2^103) / L` is the corresponding limit.

To apply these limits, implementations can count the number of messages that are
protected or rejected against the determined limits (`q` and `v` respectively).
This requires that messages cannot exceed the maximum message size (`L`) that is
chosen.

## Approximations

This analysis assumes a message-based approach to setting limits.
Implementations that use byte counting rather than message counting could use a
maximum message size (`L`) of one to determine a limit for the number of
protected messages (`q`) that can be applied with byte counting.  This results
in attributing per-message overheads to every byte, so the resulting limit could
be significantly lower than necessary.  Actions, like rekeying, that are taken
to avoid the limit might occur more often as a result.

To simplify formulae, estimates in this document elide terms that contribute
negligible advantage to an attacker relative to other terms.

In other respects, this document seeks to make conservative choices that err on
the side of overestimating attacker advantage.  Some of these assumptions are
present in the papers that this work is based on.  For instance, analyses are
simplified by using a single message size that covers both AAD and plaintext.
AAD can contribute less toward attacker advantage for confidentiality limits, so
applications where AAD comprises a significant proportion of messages might find
the estimates provided to be slightly more conservative than necessary to meet a
given goal.

This document assumes the use of non-repeating nonces.  The modes covered here
are not robust if the same nonce and key are used to protect different messages,
so deterministic generation of nonces from a counter or similar techniques is
strongly encouraged.  If an application cannot guarantee that nonces will not
repeat, a nonce-misuse resistant AEAD like AES-GCM-SIV {{?SIV=RFC8452}} is
likely to be a better choice.


# Single-Key AEAD Limits {#su-limits}

This section summarizes the confidentiality and integrity bounds and limits for modern AEAD algorithms
used in IETF protocols, including: AEAD_AES_128_GCM {{!RFC5116}}, AEAD_AES_256_GCM {{!RFC5116}},
AEAD_AES_128_CCM {{!RFC5116}}, AEAD_CHACHA20_POLY1305 {{!RFC8439}}, AEAD_AES_128_CCM_8 {{!RFC6655}}.
The limits in this section apply to using these schemes with a single key;
for settings where multiple keys are deployed (for example, when rekeying within
a connection), see {{mu-limits}}.

These algorithms, as cited, all define a nonce length (`r`) of 96 bits.  Some
definitions of these AEAD algorithms allow for other nonce lengths, but the
analyses in this document all fix the nonce length to `r = 96`.  Using other nonce
lengths might result in different bounds; for example, {{GCMProofs}} shows that
using a variable-length nonce for AES-GCM results in worse security bounds.

The CL and IL values bound the total number of encryption and forgery queries (`q` and `v`).
Alongside each advantage value, we also specify these bounds.

## AEAD_AES_128_GCM and AEAD_AES_256_GCM

The CL and IL values for AES-GCM are derived in {{AEBounds}} and summarized below.
For this AEAD, `n = 128` and `t = 128` {{GCM}}. In this example, the length `s` is the sum
of AAD and plaintext (in blocks of 128 bits), as described in {{GCMProofs}}.

### Confidentiality Limit

~~~
CA <= ((s + q + 1)^2) / 2^129
~~~

This implies the following usage limit:

~~~
q + s <= p^(1/2) * 2^(129/2) - 1
~~~

Which, for a message-based protocol with `s <= q * L`, if we assume that every
packet is size `L` (in blocks of 128 bits), produces the limit:

~~~
q <= (p^(1/2) * 2^(129/2) - 1) / (L + 1)
~~~

### Integrity Limit

<!--
    We follow {{GCMProofs}} and use the improved integrity bound from
    {{AEBounds}}, Equation (22), which gives the term (v * (L+1)) * \delta(...).
    Assuming s + q + v < 2^64, one can bound \delta(...) <= 1.7 <= 2.
-->

Assuming `s + q + v < 2^64` implies this bound:

~~~
IA <= 2 * (v * (L + 1)) / 2^128
~~~

This implies the following limit:

~~~
v <= (p * 2^127) / (L + 1)
~~~

## AEAD_CHACHA20_POLY1305

The known single-user analyses for AEAD_CHACHA20_POLY1305
{{ChaCha20Poly1305-SU}}, {{ChaCha20Poly1305-MU}} combine the confidentiality and
integrity limits into a single expression, covered below. For this AEAD, `n =
512`, `k = 256`, and `t = 128`; the length `L` is the sum of AAD and plaintext
(in blocks of 128 bits), see {{ChaCha20Poly1305-MU}}.


<!--
    In {{ChaCha20Poly1305-SU}}, L is |AAD| + |plaintext| + 1; the + 1 is one
    block length encoding.

    From {{ChaCha20Poly1305-MU}} Theorem 4.1 / 3.4:
      AE <= v * 2^25 * (L+1) / 2^t
    where t = 128.
    (NB: The bound component "c * L" (for c = 3*2^24) is upper-bounding
    2^25 * (L+1) for the worst case L = |AAD|+|m| = 2; cf. Theorem 3.4.)
-->
~~~
AEA <= (v * (L + 1)) / 2^103
~~~

This advantage is a tight reduction based on the underlying Poly1305 PRF {{!Poly1305=DOI.10.1007/11502760_3}}.
It implies the following limit:

~~~
v <= (p * 2^103) / (L + 1)
~~~

## AEAD_AES_128_CCM

The CL and IL values for AEAD_AES_128_CCM are derived from {{!CCM-ANALYSIS=DOI.10.1007/3-540-36492-7_7}}
and specified in the QUIC-TLS mapping specification {{?RFC9001}}. This analysis uses the total
number of underlying block cipher operations to derive its bound. For CCM, this number is the sum of:
the length of the associated data in blocks, the length of the ciphertext in blocks, the length of
the plaintext in blocks, plus 1.

In the following limits, this is simplified to a value of twice the length of the packet in blocks,
i.e., `2L` represents the effective length, in number of block cipher operations, of a message with
L blocks. This simplification is based on the observation that common applications of this AEAD carry
only a small amount of associated data compared to ciphertext. For example, QUIC has 1 to 3 blocks of AAD.

<!--
    In {{!CCM-ANALYSIS=DOI.10.1007/3-540-36492-7_7}}, Theorem 1+2, the terms
    l_E / l_F are the sum of block cipher applications over all encryption /
    forgery calls, which count the number of message blocks twice: once as
    |m| (resp. |c|), and once in the enconding function \beta.

    We simplify this by doubling the the packet length, using `2L` instead of
    `L`, while ignoring the usually small additional overhead of associated data.
    Hence `l_E = 2L * q` and `l_F = 2L * v`.
-->

For this AEAD, `n = 128` and `t = 128`.

### Confidentiality Limit

~~~
CA <= (2L * q)^2 / 2^n
   <= (2L * q)^2 / 2^128
~~~

This implies the following limit:

~~~
q <= sqrt((p * 2^126) / L^2)
~~~

### Integrity Limit

~~~
IA <= v / 2^t + (2L * (v + q))^2 / 2^n
   <= v / 2^128 + (2L * (v + q))^2 / 2^128
~~~

This implies the following limit:

~~~
v + (2L * (v + q))^2 <= p * 2^128
~~~

In a setting where `v` or `q` is sufficiently large, `v` is negligible compared to
`(2L * (v + q))^2`, so this this can be simplified to:

~~~
v + q <= sqrt(p) * 2^63 / L
~~~

## AEAD_AES_128_CCM_8

The analysis in {{!CCM-ANALYSIS}} also applies to this AEAD, but the reduced tag
length of 64 bits changes the integrity limit calculation considerably.

~~~
IA <= v / 2^t + (2L * (v + q))^2 / 2^n
   <= v / 2^64 + (2L * (v + q))^2 / 2^128
~~~

This results in reducing the limit on `v` by a factor of 2<sup>64</sup>.

~~~
v * 2^64 + (2L * (v + q))^2 <= p * 2^128
~~~


## Single-Key Examples

An example protocol might choose to aim for a single-key CA and IA that is at
most 2<sup>-50</sup>.  If the messages exchanged in the protocol are at most a
common Internet MTU of around 1500 bytes, then a value for `L` might be set to
2<sup>7</sup>.  {{ex-table-su}} shows limits for `q` and `v` that might be
chosen under these conditions.

| AEAD                   | Maximum q        | Maximum v      |
|:-----------------------|-----------------:|---------------:|
| AEAD_AES_128_GCM       | 2<sup>32.5</sup> | 2<sup>71</sup> |
| AEAD_AES_256_GCM       | 2<sup>32.5</sup> | 2<sup>71</sup> |
| AEAD_CHACHA20_POLY1305 | n/a              | 2<sup>46</sup> |
| AEAD_AES_128_CCM       | 2<sup>30</sup>   | 2<sup>30</sup> |
| AEAD_AES_128_CCM_8     | 2<sup>30.9</sup> | 2<sup>13</sup> |
{: #ex-table-su title="Example single-key limits"}

AEAD_CHACHA20_POLY1305 provides no limit to `q` based on the provided single-user
analyses.

The limit for `q` on AEAD_AES_128_CCM and AEAD_AES_128_CCM_8 is reduced due to a
need to reduce the value of `q` to ensure that IA does not exceed the target.
This assumes equal proportions for `q` and `v` for AEAD_AES_128_CCM.
AEAD_AES_128_CCM_8 permits a much smaller value of `v` due to the shorter tag,
which permits a higher limit for `q`.

Some protocols naturally limit `v` to 1, such as TCP-based variants of TLS, which
terminate sessions on decryption failure.  If `v` is limited to 1, `q` can be
increased to 2<sup>31</sup> for both CCM AEADs.



# Multi-Key AEAD Limits {#mu-limits}

In the multi-key setting, each user is assumed to have an independent and
uniformly distributed key, though nonces may be re-used across users with some
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
like TLS 1.3 {{TLS}} and QUIC {{?RFC9001}}. Here, the full nonce is XORed with
a secret, random offset. The bound for nonce randomization was further improved
in {{ChaCha20Poly1305-MU}}.

Results for AES-GCM with random, partially implicit nonces {{?RFC5288}} are
captured by Theorem 5.3 in {{GCM-MU2}}, which apply to protocols such as TLS 1.2
{{?RFC5246}}. Here, the implicit part of the nonce is a random value, of length
at least 32 bits and fixed per key, while we assume that the explicit part of
the nonce is chosen using a non-repeating process. The full nonce is the
concatenation of the two parts. This produces similar limits under most
conditions.  Note that implementations that choose the explicit part at random
have a higher chance of nonce collisions and are not considered for the
limits in this section.

For this AEAD, `n = 128`, `t = 128`, and `r = 96`; the key length is `k = 128`
or `k = 256` for AEAD_AES_128_GCM and AEAD_AES_128_GCM respectively.


### Authenticated Encryption Security Limit {#mu-gcm-ae}

<!--
    From {{GCM-MU2}} Theorem 4.3; for nonce randomization (XN transform).

    Let:
        - #blocks encrypted/verified overall:   \sigma = (q + v) * L
        - worst-case  o (offline work), q+v, \sigma <= 2^95
          (Theorem 4.3 requires q <= 2^(1-e)r ; this yields e >= 0.0104, hence
          d = 1,5/e -1 <= 143 <= 2^8.)

    We can simplify the Theorem 4.3 advantage bound as follows:
        - Note: Last term is 2^-48; hence any other term <= 2^-50 is negligible.
        - 1st term (../2^k):  roughly <= 2^8 * (o + q+v + \sigma) / 2^k
           roughly <= (o + (q+v)*L) / 2^(k-8)
          This is negligible for k = 256.
          For k = 128, it is negligible if o, (q+v)*L <= 2^70.
          For o <= 2^70 and B >= 2^8, it is dominated by the 2nd term;
            we assume that and hence omit the 1st term.
          If B is small and k = 128, then \sigma might be relevant and
            we can add n*\sigma/2^128
        - 2nd term (../2^n):
          \sigma*(2B + cn + 2)/2^n = \sigma*(B + 97)/2^127
          Assuming that B >> 100, the dominant term is \sigma*B/2^127
        - 3rd term (../2^2n):  <= 2^-160, negligible.
        - 4th term (../2^(k+n)):  roughly <= (\sigma^2 + 2o(q+v)) / 2^256
          <= 2^-64, negligible.
        - 5th term (2^(-r/2)):  = 2^-48

    The 5th term, ensuring that the adversary is d-repeating ({{GCM-MU2}},
    Theorem 4.2), was improved in {{ChaCha20Poly1305-MU}} Theorem 7.7 to
      2^-(\delta * r)
    for which \delta can be chosen as \delta = 2 for d < 2^9.
    As d < 2^9 does not affect the above simplifications, this only makes the
    5th term negligible (2^-192), and allows to omit it.
-->
Protocols with nonce randomization have a limit of:

~~~
AEA <= (q+v)*L*B / 2^127
~~~

This implies the following limit:

~~~
q + v <= p * 2^127 / (L * B)
~~~

This assumes that `B` is much larger than 100; that is, each user enciphers
significantly more than 1600 bytes of data.  Otherwise, `B` should be increased by 161 for
AEAD_AES_128_GCM and by 97 for AEAD_AES_256_GCM.


<!--
    From {{GCM-MU2}} Theorem 5.3; for partial random nonces (CN transform).

    Let:
        - #blocks encrypted/verified overall:   \sigma = (q + v) * L
        - length R of random implicit nonce part: R = 32 (bits), as in TLS 1.2/RFC5288
        - worst-case  o (offline work), q+v, \sigma <= 2^77  (as per 1st term)
          (Theorem 5.3 requires R >= 32 [satisfied], o <= 2^(n-2);
          yields d = (q+v)R/2^(R-1) = (q+v)/2^26.)

    We can simplify the Theorem 5.3 advantage bound as follows:
        - 1st term (../2^k):  roughly <= ((q+v)/2^26 * (o + q+v) + n*\sigma) / 2^k
           roughly <= ((q+v)*o + (q+v)^2) / 2^(k+26) + (q+v)*l / 2^(k-7)
          This is negligible for k = 256.
          The second part ("(q+v)*l / 2^(k-7)") is negligible compared to the
             first part (and the 2nd term).
          For k = 128, what remains is:  ((q+v)*o + (q+v)^2) / 2^(k+26)
             which dominates the 2nd term if q+v > B*L*2^25.
        - 2nd term (../2^n):
          \sigma*(2B + cn + 2)/2^n = \sigma*(B + 97)/2^127
          Assuming that B >> 100, the dominant term is \sigma*B/2^127
        - 3rd term (../2^2n):  <= 2^-160, negligible.
        - 4th term (../2^(k+n)):  roughly <= (\sigma^2 + 2o(q+v)) / 2^256
          <= 2^-100, negligible.
        - 5th term (2^(-7R)):  = 2^-224, negligible.
-->

Protocols with random, partially implicit nonces have the following limit,
which is similar to that for nonce randomization:

~~~
AEA <= (((q+v)*o + (q+v)^2) / 2^(k+26)) + ((q+v)*L*B / 2^127)
~~~

The first term is negligible if `k = 256`; this implies the following simplified
limits:

~~~
AEA <= (q+v)*L*B / 2^127
q + v <= p * 2^127 / (L * B)
~~~

For `k = 128`, assuming `o <= q + v` (i.e., that the attacker does not spend
more work than all legitimate protocol users together), the limits are:

<!--
    Simplifying
      p >= (((q+v)*o + (q+v)^2) / 2^(k+26)) + ((q+v)*L*B / 2^127)

    to

      p/2 >= ((q+v)*o + (q+v)^2) / 2^(k+26)
      AND
      p/2 >= (q+v)*L*B / 2^127

    and assuming o <= q+v
    yields

      q+v <= sqrt(p) * 2^76
      AND
      q+v <= p * 2^126 / (L * B)
-->

~~~
AEA <= (((q+v)*o + (q+v)^2) / 2^154) + ((q+v)*L*B / 2^127)
q + v <= min( sqrt(p) * 2^76,  p * 2^126 / (L * B) )
~~~


### Confidentiality Limit

<!--
    From {{GCM-MU2}} Theorem 4.3,
    substracting terms for Pr[Bad_7] and Pr[Bad_8],
    and applying simplifications as above (note there are no verification queries),
    we obtain:

    Adv^{mu-ae w/o INT}_RCAU <=
        2^8 * (o + q) / 2^k   +  \sigma*B/2^127

    For o <= 2^70 and any B, the 1st term is dominated by the 2nd term;
    we assume that and hence again omit the 1st term.
-->

The confidentiality advantage is essentially dominated by the same term as
the AE advantage for protocols with nonce randomization:

~~~
CA <= q*L*B / 2^127
~~~

This implies the following limit:

~~~
q <= p * 2^127 / (L * B)
~~~


<!--
    From {{GCM-MU2}} Theorem 5.3,
    subtracting terms for Pr[Bad_7] and Pr[Bad_8],
    and applying simplifications as above (note there are no verification queries),
    we obtain:

    Adv^{mu-ae w/o INT}_CGCM <=
        q * (o + q) / 2^(k+26)   +   \sigma*B/2^127
-->

Similarly, the limits for protocols with random, partially implicit nonces are:

~~~
CA <= ((q*o + q^2) / 2^(k+26)) + (q*L*B / 2^127)
q <= min( sqrt(p) * 2^76,  p * 2^126 / (L * B) )
~~~


### Integrity Limit

There is currently no dedicated integrity multi-key bound available for
AEAD_AES_128_GCM and AEAD_AES_256_GCM. The AE limit can be used to derive
an integrity limit as:

~~~
IA <= AEA
~~~

{{mu-gcm-ae}} therefore contains the integrity limits.


## AEAD_CHACHA20_POLY1305

Concrete multi-key bounds for AEAD_CHACHA20_POLY1305 are given in Theorem 7.8
in {{ChaCha20Poly1305-MU}}, covering protocols with nonce randomization like
TLS 1.3 {{TLS}} and QUIC {{?RFC9001}}.

For this AEAD, `n = 512`, `k = 256`, `t = 128`, and `r = 96`; the length (`L`) is the sum
of AAD and plaintext (in blocks of 128 bits).

### Authenticated Encryption Security Limit {#mu-ccp-ae}

<!--
    From {{ChaCha20Poly1305-MU}} Theorem 7.8; for nonce randomization (XN transform).

    Let:
        - d: the max. number of times any nonce is repeated across users
        - \delta: the nonce-randomizer result's parameter
        - d = r * (\delta + 1) - 1 < 2^9, \delta = 2 be fixed, satisfying Theorem 7.8
        - this limits the number of encryption queries to q <= r * 2^(r-1) <= 2^101
        - o, B <= 2^261 as required for Theorem 7.8

    We can simplify the Theorem 7.8 advantage bound as follows:
        - 1st term:  v([constant]* L + 3)/2^t
          Via Theorem 3.4, the more precise term is:  v * (2^25 * (L + 1) + 3) / 2^128
          The 3v/2^t summand is dominated by the rest, so we simplify to
            (v * (L + 1)) / 2^103

        - 2nd term:  d(o + q)/2^k
          For d < 2^9 (as above) and o + q <= 2^145, this is dominated by the 1st term;
          [[ 1st term <= 2nd term as long as v * (L + 1)/2^103 <= d(o + q)/2^256;
          i.e., o + q <= v * (L + 1) * 2^153 / d.
          Even for minimal values v = 1 and l = 1 in 1st term, with d < 2^9,
          this holds as long as o + q <= 2^145. ]]
            we assume that and hence omit the 2nd term.

        - 3rd term:  2o * (n - k)/2^k
          This is dominated by the 2nd term; we hence omit it.

        - 4th term:  2v * (n - k + 4t)/2^k
          This is dominated by the 1st term; we hence omit it.

        - 5th term:  (B + q)^2/2^(n+1)
          This is dominated by the 1st term as long as B + q < 2^205;
          i.e., negligible and we hence omit it.

        - 6th term:  1/2^(2t-2) = 2^-254
          This is negligible, we hence omit it.

        - 7th term:  1/2^(n - k - 2) = 2^-254
          This is negligible, we hence omit it.

        - 8th term:  1/(\delta * r)
          This is 2^-192 for the chosen \delta = 2, hence negligible and we omit it.
-->

Protocols with nonce randomization have a limit of:

~~~
AEA <= (v * (L + 1)) / 2^103
~~~

It implies the following limit:

~~~
v <= (p * 2^103) / (L + 1)
~~~

Note that this is the same limit as in the single-user case except that the
total number of forgery attempts (`v`) and maximum message length in blocks (`L`)
is calculated across all used keys.


### Confidentiality Limit

<!--
    From {{ChaCha20Poly1305-MU}} Theorem 7.8
    subtracting terms for Pr[Bad_5] and Pr[Bad_6],
    and applying simplifications as above (note there are no verification queries),
    the remaining relevant terms are:

        - 2nd term:  d(o + q)/2^k
          As d < 2^9, this is upper bounded by   (o+q)/2^247

        - 3rd term:  2o * (n - k)/2^k
          This is  o/2^247 , dominated by the 2nd term; we hence omit it.

        - 5th term:  (B + q)^2/2^(n+1)

          This is dominated by the 2nd term as long as B + q < sqrt(o+q) * 2^133.

          We omit this term on the basis that B <= qL and there is no value
          of q less than 2^100 (see below) for which B > sqrt(q) * 2^133 given
          that constraint.

          Even with a single user and a single key such that B = qL, and no
          offline work from the adversary (o = 0) the term is only relevant when
          qL = sqrt(q) * 2^133.  With q capped at 2^100, the smallest value
          of l that can result from this is 2^83, which far exceeds the maximum
          size of a single message at 2^32.

        - 8th term:  1/(\delta * r)
          This is 2^-192 for the chosen \delta = 2, hence negligible and we omit it.
-->

While the AE advantage is dominated by the number of forgery attempts `v`, those
are irrelevant for the confidentiality advantage. The relevant limit for
protocols with nonce randomization becomes dominated, at a very low level, by
the adversary's offline work `o` and the number of protected messages `q`
across all used keys:

~~~
CA <= (o + q) / 2^247)
~~~

<!--
    In addition, the restrictions on q from {{ChaCha20Poly1305-MU}} Theorem 7.8
    applies: q <= r * 2^(r-1) <= 2^101.
    We round this to 2^100; this value can be slightly increased trading off d.
-->

This implies the following simplified limit, which for most reasonable values of
`p` is dominated by a technical limitation of approximately `q = 2^100`:

~~~
q <= min( p * 2^247 - o, 2^100 )
~~~


### Integrity Limit

The AE limit for AEAD_CHACHA20_POLY1305 essentially is the integrity (multi-key)
bound. The former hence also applies to the latter:

~~~
IA <= AEA
~~~

{{mu-ccp-ae}} therefore contains the integrity limits.


## AEAD_AES_128_CCM and AEAD_AES_128_CCM_8

There are currently no concrete multi-key bounds for AEAD_AES_128_CCM or
AEAD_AES_128_CCM_8. Thus, to account for the additional
factor `u`, i.e., the number of keys, each `p` term in the confidentiality and
integrity limits is replaced with `p / u`.

The multi-key integrity limit for AEAD_AES_128_CCM is as follows.

~~~
v + q <= sqrt(p / u) * 2^63 / L
~~~

Likewise, the multi-key integrity limit for AEAD_AES_128_CCM_8 is as follows.

~~~
v * 2^64 + (2L * (v + q))^2 <= (p / u) * 2^128
~~~


## Multi-Key Examples

An example protocol might choose to aim for a multi-key AEA, CA, and IA that is at
most 2<sup>-50</sup>.  If the messages exchanged in the protocol are at most a
common Internet MTU of around 1500 bytes, then a value for `L` might be set to
2<sup>7</sup>.  {{ex-table-mu}} shows limits for `q` and `v` across all keys that
might be chosen under these conditions.

| AEAD                   | Maximum q                | Maximum v              |
|:-----------------------|-------------------------:|-----------------------:|
| AEAD_AES_128_GCM       | 2<sup>69</sup>/B         | 2<sup>69</sup>/B       |
| AEAD_AES_256_GCM       | 2<sup>69</sup>/B         | 2<sup>69</sup>/B       |
| AEAD_CHACHA20_POLY1305 | 2<sup>100</sup>          | 2<sup>46</sup>         |
| AEAD_AES_128_CCM       | 2<sup>30</sup>/sqrt(u)   | 2<sup>30</sup>/sqrt(u) |
| AEAD_AES_128_CCM_8     | 2<sup>30.9</sup>/sqrt(u) | 2<sup>13</sup>/u |
{: #ex-table-mu title="Example multi-key limits"}

The limits for AEAD_AES_128_GCM, AEAD_AES_256_GCM, AEAD_AES_128_CCM, and
AEAD_AES_128_CCM_8 assume equal proportions for `q` and `v`. The limits for
AEAD_AES_128_GCM, AEAD_AES_256_GCM and AEAD_CHACHA20_POLY1305 assume the use
of nonce randomization, like in TLS 1.3 {{TLS}} and QUIC {{?RFC9001}}.

The limits for AEAD_AES_128_GCM and AEAD_AES_256_GCM further depend on the
maximum number (`B`) of 128-bit blocks encrypted by any single key. For example,
limiting the number of messages (of size <= 2<sup>7</sup> blocks) to at most
2<sup>20</sup> (about a million) per key results in `B` of 2<sup>27</sup>, which
limits both `q` and `v` to 2<sup>42</sup> messages.

Only the limits for AEAD_AES_128_CCM and AEAD_AES_128_CCM_8 depend on the number
of used keys (`u`), which further reduces them considerably. If `v` is limited to 1,
`q` can be increased to 2<sup>31</sup>/sqrt(u) for both CCM AEADs.


# Security Considerations {#sec-considerations}

The different analyses of AEAD functions that this work is based upon generally
assume that the underlying primitives are ideal.  For example, that a
pseudorandom function (PRF) used by the AEAD is indistinguishable from a truly
random function or that a pseudorandom permutation (PRP) is indistinguishable
from a truly random permutation. Thus, the advantage estimates assume that the
attacker is not able to exploit a weakness in an underlying primitive.

Many of the formulae in this document depend on simplifying assumptions,
from differing models, which means that results are not universally applicable. When using this
document to set limits, it is necessary to validate all these assumptions
for the setting in which the limits might apply. In most cases, the goal is
to use assumptions that result in setting a more conservative limit, but this
is not always the case. As an example of one such simplification, this document
defines `v` as the total number of failed decryption queries (that is, failed forgery
attempts), whereas models usually include all forgery attempts when determining `v`.

The CA, IA, and AEA values defined in this document are upper bounds based on existing
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
