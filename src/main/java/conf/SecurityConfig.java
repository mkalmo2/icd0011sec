package conf;

import conf.security.handlers.ApiAccessDeniedHandler;
import conf.security.handlers.ApiEntryPoint;
import conf.security.handlers.ApiLogoutSuccessHandler;
import conf.security.jwt.JwtAuthenticationFilter;
import conf.security.jwt.JwtAuthorizationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@PropertySource("classpath:/application.properties")
public class SecurityConfig {

    public final static String AUTHENTICATION_INFO_KEY = "AUTHENTICATION_INFO_KEY";

    @Value("${jwt.signing.key}")
    private String jwtKey;

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http) throws Exception {

        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

//        http.formLogin();

        http.csrf().disable();
        http.logout().logoutUrl("/api/logout");

        http.authorizeHttpRequests()
                .requestMatchers("/api/home").permitAll();
        http.authorizeHttpRequests()
                .requestMatchers("/api/admin/**").hasRole("ADMIN");
        http.authorizeHttpRequests()
                .requestMatchers("/api/**").authenticated();
        http.authorizeHttpRequests()
                .requestMatchers("/**").permitAll();

        http.exceptionHandling()
                .authenticationEntryPoint(new ApiEntryPoint());

        http.exceptionHandling()
                .accessDeniedHandler(new ApiAccessDeniedHandler());

        http.logout().logoutSuccessHandler(new ApiLogoutSuccessHandler());

        http.apply(new FilterConfigurer());

        return http.build();
    }

    @Bean
    public UserDetailsService userDetailService() {
        UserDetails user = User.builder()
                .username("user")
                .password("$2a$10$e2v79LxWXANrsBB4bkbqaePjGCwruo8sUxX4m0hoYUN3dZ6pEibDG")
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("$2a$10$e2v79LxWXANrsBB4bkbqaePjGCwruo8sUxX4m0hoYUN3dZ6pEibDG")
                .roles("USER", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public static PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.debug(false);
    }

    public class FilterConfigurer extends AbstractHttpConfigurer<FilterConfigurer, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) {
            AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

//            var loginFilter = new ApiAuthenticationFilter(
//                manager, "/api/login");
//
//            http.addFilterBefore(loginFilter,
//                    UsernamePasswordAuthenticationFilter.class);
//
//            var authorizationFilter = new ApiAuthorizationFilter();
//
//            http.addFilterBefore(authorizationFilter, AuthorizationFilter.class);

            var loginFilter = new JwtAuthenticationFilter(
                manager, "/api/login", jwtKey);

            http.addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class);

            var authorizationFilter = new JwtAuthorizationFilter(jwtKey);

            http.addFilterBefore(authorizationFilter, AuthorizationFilter.class);
        }
    }

}