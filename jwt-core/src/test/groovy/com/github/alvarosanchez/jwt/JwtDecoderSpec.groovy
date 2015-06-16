package com.github.alvarosanchez.jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import spock.lang.Shared
import spock.lang.Specification

class JwtDecoderSpec extends Specification {

    void 'it can decode JWTs'() {
        given: "a JwtDecoder"
        String secret = 'secret'*8
        Map claims = [
            name: 'John Doe',
            admin: true
        ]
        JwtDecoder jwtDecoder = new JwtDecoder(secret: secret)

        and: "a JWT String"
        JWTClaimsSet claimsSet = new JWTClaimsSet()
        claims.each { k, v-> claimsSet.setCustomClaim(k as String, v) }
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet)
        JWSSigner signer = new MACSigner(secret)
        signedJWT.sign(signer)
        String generatedJwt = signedJWT.serialize()

        when:
        Map<String, Object> decodedClaims = jwtDecoder.decode(generatedJwt)

        then:
        claims.every { String k,v ->
            decodedClaims[k] == v
        }
    }

}