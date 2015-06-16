package grails.plugin.jwt

import com.nimbusds.jwt.SignedJWT
import grails.test.spock.IntegrationSpec

class JwtCodecSpec extends IntegrationSpec {

    void "it can encode objects"() {
        when:
        String parsedJwt = [name: 'John Doe', admin: true].encodeAsJwt()
        SignedJWT jwt = SignedJWT.parse(parsedJwt)

        then:
        jwt
    }
}
