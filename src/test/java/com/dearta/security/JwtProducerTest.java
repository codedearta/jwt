package com.dearta.security;

import com.dearta.security.jwt.JwtToken;
import org.junit.Test;

import java.net.InetAddress;

/**
 * Created by sepp on 27.09.15.
 */
public class JwtProducerTest {

    // https://javadigest.wordpress.com/2012/08/26/rsa-encryption-example/

    @Test
    public void verifySignatureSuccessWhenNoClaimchanged() throws Exception {
        String issuer = "a issuer";
        String secret = "secret";
        JwtToken signedToken = new JwtToken(issuer).sign(secret);
        JwtToken parsedToken = JwtToken.parseTokenFrom(signedToken.toBase64());

        parsedToken.verifySignature(secret);
    }

    @Test(expected=Exception.class)
    public void verifySignatureFailsWhenIssuerClaimChanged() throws Exception {
        String issuer = "a issuer";
        String secret = "secret";
        JwtToken signedToken = new JwtToken(issuer).sign(secret);

        signedToken.claims.put(JwtToken.CLAIM_NAME_ISSUER, "changed issuer");

        JwtToken.parseTokenFrom(signedToken.toBase64()).verifySignature(secret);
    }

    @Test(expected=Exception.class)
    public void verifyExpirationOnExpiredToken() throws Exception {
        String issuer = "a issuer";
        JwtToken unSignedToken = new JwtToken(issuer).withExpireClaim(0);
        unSignedToken.verifyExpiration();
    }


    @Test(expected=Exception.class)
    public void verifyClientIpFailsonReplayedTokenFronDifferentClient() throws Exception {
        String issuer = "a issuer";
        String clientIp = InetAddress.getLocalHost().getHostAddress();
        String wrongIp = "199.168.1.99";

        JwtToken unSignedToken = new JwtToken(issuer).withClientIpClaim(clientIp);
        unSignedToken.verifyClientIp(wrongIp);
    }
}
