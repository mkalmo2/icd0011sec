package conf.security;

import conf.security.handlers.ApiAuthFailureHandler;
import conf.security.handlers.ApiAuthSuccessHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;

public class ApiAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public ApiAuthenticationFilter(AuthenticationManager authenticationManager, String url) {
        super(url);

        setAuthenticationManager(authenticationManager);
        setAuthenticationSuccessHandler(new ApiAuthSuccessHandler());
        setAuthenticationFailureHandler(new ApiAuthFailureHandler());

        setSecurityContextRepository(new HttpSessionSecurityContextRepository());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) {

        LoginCredentials loginCredentials = new LoginCredentials();

        // Read info from HttpServletRequest.

        // Use ObjectMapper to convert Json to LoginCredentials object.

        // Info from LoginCredentials is used below.

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(
                        loginCredentials.getUsername(),
                        loginCredentials.getPassword());

        return getAuthenticationManager().authenticate(token);
    }
}
