%%%
title = "JSON Web Signatures (JWS) Multiple Payload Option"
abbrev = "jws-multi-payload"
ipr = "trust200902"
keyword = ["jose", "jws"]
docname = "draft-waite-jws-multi-payload"
category = "info"

[seriesInfo]
name = "Internet-Draft"
value = "draft-waite-jws-multi-payload-latest"
stream = "IETF"
status = "informational"

[pi]
toc = "yes"

[[author]]
initials = "D."
surname = "Waite"
fullname = "David Waite"
organization = "Ping Identity"
  [author.address]
  email = "dwaite+jose@pingidentity.com"

[[author]]
initials = "J."
surname = "Miller"
fullname = "Jeremie Miller"
organization = "Ping Identity"
  [author.address]
   email = "jmiller@pingidentity.com"

[[author]]
initials = "M."
surname = "Jones"
fullname = "Michael B. Jones"
organization = "individual"
  [author.address]
  email = "michael_b_jones@hotmail.com"
  uri = "https://self-issued.info/"

%%%

.# Abstract

The JOSE set of standards established JSON-based container formats for [signatures](https://datatracker.ietf.org/doc/rfc7515/) over a content payload using  established [algorithms](https://datatracker.ietf.org/doc/rfc7518/).

Newer algorithms are emerging which allow for additional operations on content, such as a party (other than the signer) choosing not to disclose some of the integrity-protected content. However, these algorithms often support granularity at the individual message level, creating a need to define a way to support expressing multiple content payloads as part of a single message.

This document defines a new operational mode for JSON Web Signatures that operates on a protected header and multiple binary content payloads to provide the expressivity needed for this class of algorithm. It also describes how multiple content payloads can be expressed in a manner compatible with pre-existing algorithms, albeit without the operational capabilities of newer algorithms.

{mainmatter}

# Introduction

The JOSE specifications are very widely deployed and well supported, enabling use of cryptographic primitives with a JSON representation.  JWTs [@!RFC7519] are one of the most common representations for identity and access claims.  For instance, they are used by the OpenID Connect and Secure Telephony Identity Revisited (STIR) standards.

JWTs are also used by W3C's Verifiable Credentials and are used in many Decentralized Identity systems, where they may represent rich identity claims about a subject as an issued statement, which may be presented at some point in the future to another party for verification, without active participation by the original issuer.

With these new use cases, there is an increased focus on adopting privacy-protecting cryptographic primitives. The privacy-protection focus is largely in two areas: allowing a party to reduce the amount of information from the original document which is presented to a third party, and reducing correlation from the cryptographic algorithms when presenting a single issued statement multiple times.

One commonality across these algorithms is that they either require or are computationally simplified by delineating information items into multiple content payloads (whether the algorithms refer to them as messages, attributes, or slots), which are bound together into a single cryptographic object. They then define transformations in order to modify these individual components to release, omit, or express statements on the value of those components.

This specification defines an operational mode for algorithms which are multi-payload aware, as well as JSON and compact expressions for multiple payloads. It also defines how multiple payloads can be processed by algorithms which do not support the above transformations, and how multiple payloads might be used pre-existing JWS implementations based on such algorithms.

# Conventions and Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 [@RFC2119] [@RFC8174] when, and only when, they appear in all capitals, as shown here.

This specification will use the following conventions to describe expressions for transforms and serializations:

1. A function is a transform or other operation which takes inputs and outputs a value will be described using a capitalized function name, with parameters folling in parenthesis as a comma-separated list, such as `FUNCTION(INPUT1, INPUT2)`. Functions may nest if the input to one function is the output of another.
2. A constant value is indicated with a capitalized name and no parameterized list, such as `CONSTANT`
3. Constants which are single 7-bit ASCII codes are indicated by the value, surrounded by single quotes, such as `'~'`
4. Multiple values are concatenated into a single serialized form using two vertical line or "pipe" characters, e.g. `A || B`
5. Optionality is indicated by surrounding an expression with square brackets, such as `A || [B || C]`

The following additional conventions are used for expressing serialization of variable-length lists

1. The values in a list, if needed, is indicated using a 1-based numerical suffix, such as `Payload 1`
2. A loop is indicated by double square brackets, using a suffix of n, such as `Payload 1 || [[ '~' || Payload n]]`

This specification uses the same terminology as the "JSON Web Signature" [JWS] and "JSON Web Algorithms" [JWA] specifications, as well as the `BASE64URL(OCTETS)`, `UTF8(STRING)`, and `ASCII(STRING)` encoding conventions (here referred to as functions.)

# Multiple Payload Aware Algorithms

Algorithms which support multiple payloads do not operate on the JWS Signing Input. They instead expect to receive information directly and individually as octets:

- The octets from UTF-8 encoding the protected header
- An ordered list of content payloads, each expressed as octets. Note that a single payload may be a zero length octet string, or may be omitted.

> NOTE: Need to decide if zero length and nil are worth representing as distinct, partially as compact representation will not be able to distinguish them.

Neither the protected header nor the content payloads are input in their JSON or compact serialized form, and thus are not expected to have a BASE64URL encoding applied when input for signature or validation.

Algorithms which are not aware of multiple payloads are instead expected to operate on the JWS signing input form, described below.

# Multi Payload Serializations

## JSON Serialization

For the JWS JSON serialization, multiple payloads are expressed via the new "payloads" member, which is an array where each entry is either a base64url-encoded content payload value or the JSON value `null`. Implementations MUST verify the "payload" member is absent when "payloads" is present.

## Compact Serialization

For the JWS Compact serialization, multiple payloads are expressed by base64url-encoding each, then concatenating them into a single textual value with the tilde '~' character. This value is then expressed in lieu of a single base64-url encoded payload.

```
   BASE64URL(UTF8(JWS Protected Header))
   || '.' || BASE64URL(JWS Payload 1) ||
   [[ '~' || BASE64URL(JWS Payload n) ]]
   || '.' || BASE64URL(JWS Signature)
```

For example, if the protected header coincidentally base64url-encoded to "HEADER", the three payloads base64url-encoded to "PAYLOAD1", "PAYLOAD2", and "PAYLOAD3", and the signature to "SIGN", the compact serialization would be:

```
   HEADER.PAYLOAD1~PAYLOAD2~PAYLOAD3.SIGN
```

JWS Compact serialization represents omitted payloads as zero length payloads, and both base64url-encode to a zero length character sequence. If the second payload value had been omitted, the representation would have been:

```
   HEADER.PAYLOAD1~~PAYLOAD3.SIGN
```

# JWS Signing Input

For algorithms which are not multiple payload aware, they are expected to continue to operate on a JWS signing input. When Multiple payloads are used, the JWS signing input is:

```
   BASE64URL(JWS Protected Header)
   || '.' || BASE64URL(JWS Payload 1) ||
   [[ '~' || BASE64URL(JWS Payload n) ]]
```

# The "mp" Header Parameter {#mp-header}

This Header Parameter indicates the signature is protecting multiple content payloads.

The value `true` modifies the representation in JSON and compact encodings, as well as the JWS signing input, to to the rules above.

Multi-payload aware algorithms cannot operate on JWS signing input, and MUST be assumed to be operating as if `"mp"` was specified as `true`. A `"mp"` header of `false` is not legal in this scenario, and it is RECOMMENDED that the `"mp"` header not be specified.

Applications which do not specify multi-payload behavior can be assumed to be operating in a mode where `"mp"` is `false`. Applications MAY either indicate this value be specified explicitly, or be assumed by context.

# Interactions with Unencoded Payload Option

[RFC7797] specifies the unencoded payload option, which allows for payloads that can be expressed without base64url-encoding to skip the payload transformation, altering transforms as well as the JWS signed input. This is done via the `"b64"` protected header being `true`. The payload in such a case can include both the base64url alphabet as well as the tilde character `~`.

As the unencoded payload option describes how to encoded multiple payloads, the `"b64"` protected header does not have an effect on multi-payload processing. That said, the two headers have compatible payloads and JWS signing input, by noting such an unencoded payload input is a _combined payload serialization_ of the multi-payload input, defined as:

```
   BASE64URL(JWS Payload 1) ||
   [[ '~' || BASE64URL(JWS Payload n) ]]
```

## Compatibility mode with implementations without multi-payload support

The unencoded payload option can be used in concert with multi-payload support when using algorithms which are not multi-payload aware, and communicating with compact serialization. This provides compatibility with JWS implementations without multi-payload support, which will fall back to interpreting the payload as a combined payload serialization. For such implementations, another layer of the application would be responsible for decomposing and interpreting the combined payload.

When operating in compatibility mode, the protected header should indicate:

* a non multi-payload-aware algorithm
* a `"mp"` header of `true`, indicating that multiple payloads for JWS implmentations which support such a feature
* a `"b64"` header of `false`, indicating that the payload is not encoded
* a `"crit"` header including `"b64"` but not including `"mp"`.

As this is the only valid combination of `"mp"` with `"b64"` as `false`, a multi-payload aware JWS implementation SHOULD consider that they satisfy the `"crit"` requirement for `"b64"`, even if they otherwise do not support unencoded payloads.

Due to the difference in JSON serialization between the `payloads` value defined for multi-payload support and the `payload` value expected by the unencoded payload option, you MUST NOT use JSON serialization for transmission when operating with this combination of header parameters.

# Indicating Multi-payload is required

When not using the compatibility mode described above, the JWS MUST use existing mechanisms to indicate the requirements of the message, and MUST NOT rely on side effects such as base64url decoding errors to prevent consumption by incompatible implementations.

As such, the following two mechanisms are described to explicitly limit compatibility:

1. A multi-payload-aware algorithm MUST only be supported by a multi-payload compatible JWS implementation. Implementations which do not understand multiple payloads will fail when they encounter an algorithm they do not support

2. When an `"mp"` header of `true` is used with an algorithm that is not multiple payload aware, a `"crit"` header including `"mp"` MUST be supplied.

# Detached payload content

Appendix F of [JWS] describes how to represent JWSs with detached content, by applications omitting the payload in the transmitted serialization, and having the application reconsistitute the payload member to do integrity verification.

The steps to detach all payloads from a multi-payload JWS are similar, with the caveat that the JSON serialization would now have the `payloads` key omitted in such a scenario.

It is RECOMMENDED that applications describe when and how the detached content is to be used, taking particular caution around confusion that could result if only _some_ of the payloads have been detached.

# Security Considerations

TODO Security

# IANA Considerations

## JSON Web Signature and Encryption Header Parameter Registration

This specification registers the "mp" Header Parameter defined in Section (#mp-header) of this specification in the IANA " JSON Web Signature and Encryption Header Parameters" registry established by [JWS]

### Registry Contents

* Header Parameter Name: "mp"
* Header Parameter Description: Multiple Payload Encoding
   o  Header Parameter Usage Location(s): JWS
   o  Change Controller: IESG
   o  Specification Document(s): TBD

{backmatter}

# Acknowledgments

TODO acknowledge.
