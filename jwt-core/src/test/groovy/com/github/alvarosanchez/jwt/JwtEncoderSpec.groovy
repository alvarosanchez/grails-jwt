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

class JwtEncoderSpec extends Specification {

    void 'it can encode Maps to JWT string'() {
        given: "a JwtEncoder"
        String secret = 'secret'*8
        Map claims = [
            name: 'John Doe',
            admin: true
        ]
        JwtEncoder jwtEncoder = new JwtEncoder(secret: secret)

        when: "a map is encoded"
        String encodedJwt = jwtEncoder.encode(claims)

        then: "a JWT string is produced"
        encodedJwt

        when: "we try to parse back the JWT string"
        SignedJWT jwt = SignedJWT.parse(encodedJwt)

        then: "it can be verified with the same secret, and all the original claims are present"
        jwt.verify(new MACVerifier(secret))
        claims.every { String k,v ->
            jwt.JWTClaimsSet.allClaims[k] == v
        }
    }


}