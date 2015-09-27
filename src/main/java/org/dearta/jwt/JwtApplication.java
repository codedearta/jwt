package org.dearta.jwt;

import io.dropwizard.Application;
import io.dropwizard.assets.AssetsBundle;
import io.dropwizard.auth.AuthFactory;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import org.dearta.jwt.configuration.JwtConfiguration;
import org.dearta.jwt.resources.AuthResource;

/**
 * Created by sepp on 26.09.15.
 */
public class JwtApplication extends Application<JwtConfiguration> {

    public static void main(String[] args) throws Exception {
        new JwtApplication().run(args);
    }

    @Override
    public String getName() {
        return "Jwt Application";
    }

    @Override
    public void initialize(Bootstrap<JwtConfiguration> bootstrap) {
        bootstrap.addBundle(new AssetsBundle());
    }

    @Override
    public void run(JwtConfiguration configuration, Environment environment) {
        environment.jersey().register(AuthFactory.binder(new JwtAuthenticatorFactory<User>(new JwtAuthenticator(configuration.getKey()),
                this.getName(),
                User.class)));

        environment.jersey().setUrlPattern("/api/*");
        environment.jersey().register(new AuthResource(configuration));
    }
}
