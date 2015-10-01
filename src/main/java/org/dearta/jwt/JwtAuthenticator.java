package org.dearta.jwt;

import com.google.common.base.Optional;
import io.dropwizard.auth.Authenticator;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Created by sepp on 26.09.15.
 */
public class JwtAuthenticator implements Authenticator<String, User> {

    private String secret;

    public JwtAuthenticator(String secret) {
        this.secret = secret;
    }

    public Optional<User> authenticate(String jwtTokenString) {
        try {
            JwtToken jwtToken = JwtToken
                    .parseTokenFrom(jwtTokenString)
                    .verifySignature(this.secret)
                    .verifyExpiration();

            User user = new User(jwtToken.claims.get(JwtToken.CLAIM_NAME_USER));
            return Optional.of(user);
        } catch (Exception e) {
            return Optional.absent();
        }
    }
}