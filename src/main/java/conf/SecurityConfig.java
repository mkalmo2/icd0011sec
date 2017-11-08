package conf;

import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import security.RestAuthenticationFilter;
import security.handlers.RestAuthFailureHandler;
import security.handlers.RestAuthSuccessHandler;
import security.handlers.RestLogoutSuccessHandler;

import javax.servlet.Filter;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        http.authorizeRequests()
                .antMatchers("/api/login").permitAll()
                .antMatchers("/api/logout").permitAll()
                .antMatchers("/api/**").hasAnyRole("USER")
                .antMatchers("/**").permitAll();


        http.addFilterAfter(restLoginFilter("/api/login"), LogoutFilter.class);

        http.logout()
                .logoutUrl("/api/logout")
                .logoutSuccessHandler(new RestLogoutSuccessHandler());
    }

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {

        builder.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("user")
                .password("$2a$10$8nCYfy04c4I7/lblliFdcegtIyBPbE7I0jAlp0XIznUV4JIodnDHe")
                .roles("USER");

        // builder.jdbcAuthentication()
        //         .passwordEncoder()
        //         .dataSource()
    }

    public Filter restLoginFilter(String url) throws Exception {
        RestAuthenticationFilter filter = new RestAuthenticationFilter(url);

        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(new RestAuthSuccessHandler());
        filter.setAuthenticationFailureHandler(new RestAuthFailureHandler());

        return filter;
    }
}