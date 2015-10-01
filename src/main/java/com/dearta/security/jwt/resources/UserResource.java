package com.dearta.security.jwt.resources;

import com.codahale.metrics.annotation.Timed;
import com.dearta.security.jwt.User;
import io.dropwizard.auth.Auth;

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
