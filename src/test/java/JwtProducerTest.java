import org.dearta.jwt.JwtToken;
import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNull.notNullValue;

/**
 * Created by sepp on 27.09.15.
 */
public class JwtProducerTest {

    @Test
    public void createToken() throws Exception {
        String issuer = "a issuer";
        String secret = "secret";
        JwtToken signedToken = new JwtToken(issuer).withExpireClaim(1).sign(secret);

        assertThat(signedToken.claims.get(JwtToken.CLAIM_NAME_ISSUER), equalTo(issuer));
        assertThat(signedToken.signature, notNullValue());

        JwtToken.verifyTokenSignature(signedToken.toBase64(), issuer, secret);

        JwtToken.verifyTokenSignature(JwtToken.AUTHENTICATION_SCHEME + " " + signedToken.toBase64(), issuer, secret)
                .verifyExpiration();
    }

    @Test(expected=Exception.class)
    public void verifyExpiration() throws Exception {
        String issuer = "a issuer";
        JwtToken unSignedToken = new JwtToken(issuer).withExpireClaim(0);
        unSignedToken.verifyExpiration();
    }
}
