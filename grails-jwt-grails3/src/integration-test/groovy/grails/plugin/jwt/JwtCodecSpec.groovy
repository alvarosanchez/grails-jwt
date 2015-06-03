package grails.plugin.jwt

import com.nimbusds.jwt.SignedJWT
import grails.test.mixin.integration.Integration
import spock.lang.*

@Integration
class JwtCodecSpec extends Specification {

    void "it can encode objects"() {
        when:
        String parsedJwt = [name: 'John Doe', admin: true].encodeAsJwt()
        SignedJWT jwt = SignedJWT.parse(parsedJwt)

        then:
        jwt
    }
}
