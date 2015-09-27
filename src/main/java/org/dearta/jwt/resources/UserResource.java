package org.dearta.jwt.resources;

import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import org.dearta.jwt.User;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

/**
 * Created by sepp on 27.09.15.
 */
@Path("user")
public class UserResource {

    @GET
    @Timed
    public User get(@Auth User user) {
        return user;
    }
}
