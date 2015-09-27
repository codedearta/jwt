import org.dearta.jwt.JwtToken;
import org.hamcrest.CoreMatchers;
import org.junit.Test;

import java.util.Base64;

import static java.util.Collections.singletonMap;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;

/**
 * Created by sepp on 27.09.15.
 */
public class JwtProducerTest {

    @Test
    public void createToken() throws Exception {
        String secret = "secret";
        JwtToken token = new JwtToken(singletonMap("user", "sepp"), secret);

        byte[] encoded = Base64.getEncoder().encode("Hello".getBytes());
        String decoded = new String(Base64.getDecoder().decode(encoded));

        assertThat(decoded, equalTo("Hello"));
        assertThat(token, notNullValue());
        assertThat(token.headers.get("alg"), CoreMatchers.equalTo("HS256"));
        assertThat(token.headers.get("typ"), CoreMatchers.equalTo("JWT"));
        assertThat(token.claims.get("user"), CoreMatchers.equalTo("sepp"));
        //assertThat(token.toBase64(), CoreMatchers.equalTo("ewogICJ0eXAiIDogIkpXVCIsCiAgImFsZyIgOiAiSFMyNTYiCn0=.ewogICJ1c2VyIiA6ICJzZXBwIgp9.QgD49hT86DCcWJS+pcqh5jykQP3Dr7K5F7+9j/xAi1I="));
        assertThat(JwtToken.verifyToken(JwtToken.AUTHENTICATION_SCHEME + token.toBase64(), secret), is(true));
    }
}
