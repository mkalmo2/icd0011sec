package conf;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import security.ApiAuthenticationFilter;
import security.handlers.*;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        // other configurations
    }

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {

        // configure user and password info

    }

    public Filter restLoginFilter(String url) throws Exception {
        ApiAuthenticationFilter filter = new ApiAuthenticationFilter(url);

        filter.setAuthenticationManager(authenticationManager());

        // add success and failure handlers

        return filter;
    }
}