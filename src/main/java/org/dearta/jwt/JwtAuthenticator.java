package org.dearta.jwt;

import com.google.common.base.Optional;
import io.dropwizard.auth.Authenticator;

import java.time.LocalDate;

/**
 * Created by sepp on 26.09.15.
 */
public class JwtAuthenticator implements Authenticator<String, User> {

    private String secret;

    public JwtAuthenticator(String secret) {
        this.secret = secret;
    }

    public Optional<User> authenticate(String jwtToken) {

        try {
            if(JwtToken.verifyToken(jwtToken, this.secret)) {
                JwtToken jwtToken1 = JwtToken.parseToken(jwtToken);
                User user = new User(jwtToken1.claims.get("user"));
                return Optional.of(user);
            }
        } catch (Exception e) {
            return Optional.absent();
        }
        return Optional.absent();
    }
}