package com.github.alvarosanchez.jwt

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.SignedJWT
import groovy.transform.CompileStatic

import java.text.ParseException

@CompileStatic
class JwtDecoder {

    String secret

    Map<String, Object> decode(String jwt) {
        SignedJWT signedJWT

        try {
            signedJWT = SignedJWT.parse(jwt)
        } catch (ParseException pe) {
            throw new RuntimeException(pe)
        }

        try {
            signedJWT.verify(new MACVerifier(secret))
            return signedJWT.JWTClaimsSet.allClaims
        } catch (JOSEException je) {
            throw new RuntimeException(je)
        }
    }

}
