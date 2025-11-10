package conf.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.withDefaults;

@EnableWebSecurity
@PropertySource("classpath:/application.properties")
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        PathPatternRequestMatcher.Builder mvc = withDefaults().basePath("/");

        http.with(new FilterConfigurer(), Customizer.withDefaults());

        return http.build();
    }

    public static class FilterConfigurer extends AbstractHttpConfigurer<FilterConfigurer, HttpSecurity> {
        @Override
        public void configure(HttpSecurity http) {
            AuthenticationManager manager = http.getSharedObject(AuthenticationManager.class);

        }
    }

    @Bean
    public UserDetailsService userDetailService() {
        UserDetails user = User.builder()
                .username("user")
                .password("$2a$10$e2v...")
                .roles("USER")
                .build();

        UserDetails admin = User.builder()
                .username("admin")
                .password("$2a$10$e2v...")
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
        return web -> web.debug(false);
    }
}