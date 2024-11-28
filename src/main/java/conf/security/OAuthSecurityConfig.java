package conf.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.PropertySource;
import org.springframework.core.env.Environment;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
@PropertySource("classpath:/application.properties")
public class OAuthSecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(
            HttpSecurity http) throws Exception {

        http.authorizeHttpRequests(httpSecurity ->
                httpSecurity.anyRequest().authenticated())
                .oauth2Login(withDefaults());

        http.with(new FilterConfigurer(), Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public ClientRegistrationRepository
            clientRegistrationRepository(Environment env) {

        String clientId = env.getProperty("google.clientId");
        String clientSecret = env.getProperty("google.clientSecret");

        var reg = CommonOAuth2Provider.GOOGLE.getBuilder("google")
                .clientId(clientId).clientSecret(clientSecret).build();

        return new InMemoryClientRegistrationRepository(reg);
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return web -> web.debug(false);
    }

    public static class FilterConfigurer
            extends AbstractHttpConfigurer<FilterConfigurer, HttpSecurity> {

        @Override
        public void configure(HttpSecurity http) {
            var filter = new InfoPage();

            http.addFilterAfter(filter, AuthorizationFilter.class);
        }
    }

    public static class InfoPage extends OncePerRequestFilter {

        @Override
        protected void doFilterInternal(HttpServletRequest request,
                                        HttpServletResponse response,
                                        FilterChain chain) throws IOException, ServletException {

            if (!"/info".equals(request.getRequestURI())) {
                chain.doFilter(request, response);
                return;
            }

            response.setStatus(200);
            response.setContentType("text/plain");
            response.getWriter().println("Authentication info\n\n");

            var auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getPrincipal() instanceof OidcUser user) {
                response.getWriter().println(
                        user.getClaims().get("email"));
            } else {
                response.getWriter().println("missing...");
            }
        }
    }

}