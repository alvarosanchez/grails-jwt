package grails.plugin.jwt

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.crypto.MACSigner
import com.nimbusds.jose.crypto.MACVerifier
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import spock.lang.Shared
import spock.lang.Specification

class JwtCodecCoreSpec extends Specification {

    @Shared Map claims = [
        name: 'John Doe',
        admin: true
    ]

    @Shared String secret = 'secret'*8

    void 'it can encode Maps to JWT string'() {
        given:
        JwtCodecCore.secret = secret

        when:
        String encodedJwt = JwtCodecCore.encode(claims)
        SignedJWT jwt = SignedJWT.parse(encodedJwt)

        then:
        jwt.verify(new MACVerifier(secret))
        println jwt.JWTClaimsSet.allClaims
        claims.every { String k,v ->
            jwt.JWTClaimsSet.allClaims[k] == v
        }
    }

    void 'it can decode JWTs'() {
        given:
        JwtCodecCore.secret = secret
        SignedJWT jwt
        JWTClaimsSet claimsSet = new JWTClaimsSet()
        claims.each { k,v-> claimsSet.setCustomClaim(k, v) }
        SignedJWT signedJWT = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet)
        JWSSigner signer = new MACSigner(secret)
        signedJWT.sign(signer)
        String generatedJwt = signedJWT.serialize()

        when:
        Map<String, Object> decodedClaims = JwtCodecCore.decode(generatedJwt)

        then:
        claims.every { String k,v ->
            decodedClaims[k] == v
        }
    }

}