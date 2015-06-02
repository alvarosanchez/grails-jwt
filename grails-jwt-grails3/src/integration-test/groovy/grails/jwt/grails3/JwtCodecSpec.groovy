package grails.jwt.grails3

import com.nimbusds.jwt.SignedJWT
import grails.test.mixin.integration.Integration
import grails.transaction.*
import spock.lang.*

@Integration
@Rollback
class JwtCodecSpec extends Specification {

    void "it can encode objects"() {
        when:
        String parsedJwt = [name: 'John Doe', admin: true].encodeAsJwt()
        SignedJWT jwt = SignedJWT.parse(parsedJwt)

        then:
        jwt
    }
}
