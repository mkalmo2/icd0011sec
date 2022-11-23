package conf.security.api;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import conf.security.handlers.ApiAuthFailureHandler;
import conf.security.handlers.ApiAuthSuccessHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.util.stream.Collectors;

import static conf.SecurityConfig.AUTHENTICATION_INFO_KEY;

public class ApiAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public ApiAuthenticationFilter(AuthenticationManager authenticationManager, String url) {
        super(url);

        setAuthenticationManager(authenticationManager);
        setAuthenticationSuccessHandler(new ApiAuthSuccessHandler());
        setAuthenticationFailureHandler(new ApiAuthFailureHandler());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
                                                HttpServletResponse response) throws IOException {

        String json = request.getReader().lines().collect(Collectors.joining("\n"));

        LoginCredentials loginCredentials;
        try {
            loginCredentials = new ObjectMapper().readValue(json, LoginCredentials.class);
        } catch (JsonProcessingException e) {
            throw new BadCredentialsException("", e);
        }

        UsernamePasswordAuthenticationToken token =
                new UsernamePasswordAuthenticationToken(
                    loginCredentials.getUserName(),
                        loginCredentials.getPassword());

        var authentication = getAuthenticationManager().authenticate(token);

        saveToSession(request, authentication);

        return authentication;
    }

    protected void saveToSession(HttpServletRequest request, Authentication authentication) {
        request.getSession().setAttribute(AUTHENTICATION_INFO_KEY, authentication);
    }
}
