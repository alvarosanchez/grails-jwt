import com.github.alvarosanchez.jwt.JwtDecoder
import com.github.alvarosanchez.jwt.JwtEncoder

class JwtCodec {

    public static String secret

    static encode = { Object obj -> new JwtEncoder(secret: secret).encode(obj as Map<String, Object>) }
    static decode = { String str -> new JwtDecoder(secret: secret).decode(str) }

}
