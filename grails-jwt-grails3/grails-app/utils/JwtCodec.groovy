import grails.plugin.jwt.JwtCodecCore

/**
 * TODO: write doc
 */
class JwtCodec {

    static encode = JwtCodecCore.encode
    static decode = JwtCodecCore.decode

}
