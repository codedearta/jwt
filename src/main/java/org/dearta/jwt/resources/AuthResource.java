package org.dearta.jwt.resources;

import com.codahale.metrics.annotation.Timed;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.auth.Auth;
import org.dearta.jwt.JwtToken;
import org.dearta.jwt.User;
import org.dearta.jwt.configuration.JwtConfiguration;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import java.util.Collections;
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
    public Map<String, String> post(Credentials credentials) throws Exception {
        JwtToken token = new JwtToken(Collections.singletonMap("user", credentials.username), jwtConfiguration.getKey());
        //NewCookie cookies = new NewCookie(new Cookie("jwtToken", token.toBase64()));

        Map<String, String> response = new HashMap<String, String>();
        response.put("access_token", token.toBase64());
        response.put("token_type","Bearer");
        response.put("expires_in","");

        return response;

        //return Response.status(Response.Status.OK).type(MediaType.TEXT_HTML).entity(response).cookie(cookies).build();
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
