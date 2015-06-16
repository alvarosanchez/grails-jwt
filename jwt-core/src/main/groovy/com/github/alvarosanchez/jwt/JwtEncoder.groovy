package com.github.alvarosanchez.jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import groovy.time.TimeCategory

class JwtEncoder {

    String secret

    String subject

    Integer expiration

    public static final Integer DEFAULT_EXPIRATION = 3600

    String encode(Map<String, Object> json) {
        JWTClaimsSet claimsSet = new JWTClaimsSet()
        claimsSet.setSubject(subject)

        Date now = new Date()
        claimsSet.setIssueTime(now)
        use(TimeCategory) {
            claimsSet.setExpirationTime(now + (expiration?:DEFAULT_EXPIRATION).seconds)
        }

        json.each { String k, Object v ->
            claimsSet.setCustomClaim(k, v)
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet)
        JWSSigner signer = new MACSigner(secret)
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }

}
