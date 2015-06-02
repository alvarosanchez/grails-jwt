package grails.plugin.jwt

import com.nimbusds.jose.JOSEException
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import groovy.time.TimeCategory

import java.text.ParseException

class JwtCodecCore {

    static String secret
    static String subject
    static Integer expiration

    static final Integer DEFAULT_EXPIRATION = 3600

    static encode = { Object obj ->
        checkSecret()
        if (!obj instanceof Map) throw new RuntimeException('Only maps can be encoded')
        SignedJWT jwt

        JWTClaimsSet claimsSet = new JWTClaimsSet()
        claimsSet.setSubject(subject)

        Date now = new Date()
        claimsSet.setIssueTime(now)
        use(TimeCategory) {
            claimsSet.setExpirationTime(now + (expiration?:DEFAULT_EXPIRATION).seconds)
        }

        obj.each {k,v ->
            claimsSet.setCustomClaim(k, v)
        }

        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet)
        JWSSigner signer = new MACSigner(secret)
        signedJWT.sign(signer)

        return signedJWT.serialize()
    }

    static decode = { String str ->
        checkSecret()
        SignedJWT jwt

        try {
            jwt = SignedJWT.parse(str)
        } catch (ParseException pe) {
            throw new RuntimeException(pe)
        }

        try {
            jwt.verify(new MACVerifier(secret))
            return jwt.JWTClaimsSet.allClaims
        } catch (JOSEException je) {
            throw new RuntimeException(je)
        }
    }

    private static checkSecret() {
        if (!secret) throw new RuntimeException('JWT secret not defined. Please give a value to grails.plugin.jwt.secret in your configuration file')
    }

}
