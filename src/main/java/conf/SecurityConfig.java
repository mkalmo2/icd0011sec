package conf;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import security.ApiAuthenticationFilter;
import security.jwt.JwtAuthenticationFilter;
import security.jwt.JwtAuthorizationFilter;
import security.handlers.*;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
@PropertySource("classpath:/application.properties")
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Value("${jwt.signing.key}")
    private String jwtKey;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http.csrf().disable();

        http.authorizeRequests()
                .antMatchers("/api/login").permitAll()
                .antMatchers("/api/logout").permitAll()
                .antMatchers("/api/home").permitAll()
                .antMatchers("/api/admin/**").hasRole("ADMIN")
                .antMatchers("/api/**").authenticated()
                .antMatchers("/**").permitAll();

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

        http.exceptionHandling().authenticationEntryPoint(new ApiEntryPoint());
        http.exceptionHandling().accessDeniedHandler(new ApiAccessDeniedHandler());

        http.logout().logoutUrl("/api/logout");
        http.logout().logoutSuccessHandler(new ApiLogoutSuccessHandler());

        var jwtAuthFilter = new JwtAuthorizationFilter(authenticationManager(), jwtKey);
        var jwtLoginFilter = new JwtAuthenticationFilter(
                authenticationManager(), "/api/login", jwtKey);

        http.addFilterBefore(jwtAuthFilter, LogoutFilter.class);
        http.addFilterAfter(jwtLoginFilter, LogoutFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {

        builder.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("user")
                .password("$2a$10$Qo9GH3GALfdoXZchyE13O.r6m4GNX6voKiPhpfCaWkQoG8d1E756i")
                .roles("USER")
                .and()
                .withUser("admin")
                .password("$2a$10$Qo9GH3GALfdoXZchyE13O.r6m4GNX6voKiPhpfCaWkQoG8d1E756i")
                .roles("ADMIN");
    }

}