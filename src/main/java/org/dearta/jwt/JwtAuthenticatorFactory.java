package org.dearta.jwt;

import com.google.common.base.Optional;
import com.google.common.io.BaseEncoding;
import io.dropwizard.auth.AuthFactory;
import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.DefaultUnauthorizedHandler;
import io.dropwizard.auth.UnauthorizedHandler;
import io.dropwizard.auth.basic.BasicCredentials;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.InternalServerErrorException;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class JwtAuthenticatorFactory<T> extends AuthFactory<String, T> {
    private static final Logger LOGGER = LoggerFactory.getLogger(JwtAuthenticatorFactory.class);
    private final boolean required;
    private final Class<T> generatedClass;
    private final String realm;
    private String prefix = "Barer";
    private UnauthorizedHandler unauthorizedHandler = new DefaultUnauthorizedHandler();
    @Context
    private HttpServletRequest request;

    public JwtAuthenticatorFactory(Authenticator<String, T> authenticator, String realm, Class<T> generatedClass) {
        super(authenticator);
        this.required = false;
        this.realm = realm;
        this.generatedClass = generatedClass;
    }

    private JwtAuthenticatorFactory(boolean required, Authenticator<String, T> authenticator, String realm, Class<T> generatedClass) {
        super(authenticator);
        this.required = required;
        this.realm = realm;
        this.generatedClass = generatedClass;
    }

    public JwtAuthenticatorFactory<T> prefix(String prefix) {
        this.prefix = prefix;
        return this;
    }

    public JwtAuthenticatorFactory<T> responseBuilder(UnauthorizedHandler unauthorizedHandler) {
        this.unauthorizedHandler = unauthorizedHandler;
        return this;
    }

    public AuthFactory<String, T> clone(boolean required) {
        return (new JwtAuthenticatorFactory(required, this.authenticator(), this.realm, this.generatedClass)).prefix(this.prefix).responseBuilder(this.unauthorizedHandler);
    }

    public void setRequest(HttpServletRequest request) {
        this.request = request;
    }

    public T provide() {
        if(this.request != null) {
            String header = this.request.getHeader("Authorization");

            try {
                if(header != null) {

                    Optional<T> result = this.authenticator().authenticate(header);
                    if(result.isPresent()) {
                        return result.get();
                    }

//                    int e = header.indexOf(32);
//                    if(e > 0) {
//                        String method = header.substring(0, e);
//                        if(this.prefix.equalsIgnoreCase(method)) {
//                            String decoded = new String(BaseEncoding.base64().decode(header.substring(e + 1)), StandardCharsets.UTF_8);
//                            int i = decoded.indexOf(58);
//                            if(i > 0) {
//                                String username = decoded.substring(0, i);
//                                String password = decoded.substring(i + 1);
//                                BasicCredentials credentials = new BasicCredentials(username, password);
//                                Optional result = this.authenticator().authenticate(credentials);
//                                if(result.isPresent()) {
//                                    return result.get();
//                                }
//                            }
//                        }
//                    }
                }
            } catch (IllegalArgumentException var10) {
                LOGGER.warn("Error decoding jwt token", var10);
            } catch (AuthenticationException var11) {
                LOGGER.warn("Error verifying jwt token", var11);
                throw new InternalServerErrorException();
            }
        }

        if(this.required) {
            throw new WebApplicationException(this.unauthorizedHandler.buildResponse(this.prefix, this.realm));
        } else {
            return null;
        }
    }

    public Class<T> getGeneratedClass() {
        return this.generatedClass;
    }
}
