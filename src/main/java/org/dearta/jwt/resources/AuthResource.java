package org.dearta.jwt.resources;

import com.codahale.metrics.annotation.Timed;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.auth.Auth;
import org.dearta.jwt.JwtToken;
import org.dearta.jwt.User;
import org.dearta.jwt.configuration.JwtConfiguration;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by sepp on 26.09.15.
 */
@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    private JwtConfiguration jwtConfiguration;

    public AuthResource(JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }

    @POST
    @Timed
    @Consumes(MediaType.APPLICATION_JSON)
    public Map<String, String> post(Credentials credentials, @Context HttpServletRequest request) throws Exception {

        JwtToken token = new JwtToken("DEARTA")
                .withUserClaim(credentials.username)
                .withIdClaim()
                .withClientIpClaim(request.getRemoteAddr())
                .withExpireClaim(60)
                .sign(jwtConfiguration.getKey());

        Map<String, String> response = new HashMap<String, String>();
        response.put("access_token", token.toBase64());
        response.put("token_type","Bearer");
        response.put("expires_in", token.claims.get(JwtToken.CLAIM_NAME_EXPIRE));

        return response;
    }


    @GET
    @Timed
    public User get(@Auth User user) {
        return user;
    }

    static class Credentials {
        @JsonProperty String username;
        @JsonProperty String password;
    }
}
