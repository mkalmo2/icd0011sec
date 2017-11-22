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

        http.authorizeRequests()
                .antMatchers("/api/login").permitAll()
                .antMatchers("/api/logout").permitAll()
                .antMatchers("/api/**").hasAnyRole("USER")
                .antMatchers("/**").permitAll();

        http.exceptionHandling().authenticationEntryPoint(new ApiEntryPoint());
        http.exceptionHandling().accessDeniedHandler(new ApiAccessDeniedHandler());

        http.logout()
                .logoutUrl("/api/logout")
                .logoutSuccessHandler(new ApiLogoutSuccessHandler());

        http.addFilterAfter(restLoginFilter("/api/login"), LogoutFilter.class);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder builder) throws Exception {

        builder.inMemoryAuthentication()
                .passwordEncoder(new BCryptPasswordEncoder())
                .withUser("user")
                .password("$2a$10$fePEVsB48us3cscETLHd6.Sf6XHz9OC.pbhxPNvtiY1iSZBx4gIfq")
                .roles("USER");

    }

    public Filter restLoginFilter(String url) throws Exception {
        ApiAuthenticationFilter filter = new ApiAuthenticationFilter(url);

        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationSuccessHandler(new ApiAuthSuccessHandler());
        filter.setAuthenticationFailureHandler(new ApiAuthFailureHandler());

        return filter;
    }
}