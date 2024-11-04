package test;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import conf.security.jwt.JwtHelper;
import conf.security.TokenInfo;
import org.junit.jupiter.api.Test;

import java.time.LocalDateTime;
import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.Is.is;
import static org.junit.jupiter.api.Assertions.assertThrows;

public class JwtHelperTest {

    private final JwtHelper jwt = new JwtHelper(
            "****************** random key ******************" +
            "kr6m4GNX6voKiPh3pfCaWkQoG8d1E756i6m4GNX6voKiP2hp");

    @Test
    public void canEncodeAndDecode() {

        var tokenInfo = new TokenInfo("user", List.of("user", "admin"));

        String tokenAsString = jwt.encode(tokenInfo);

        var decoded = jwt.decode(tokenAsString);

        assertThat(decoded.getUsername(), is(tokenInfo.getUsername()));
        assertThat(decoded.getRoles(), is(tokenInfo.getRoles()));
    }

    @Test
    public void failsOnExpiredToken() {

        String tokenAsString = jwt.encode(
                new TokenInfo("user", ""), LocalDateTime.now().minusMinutes(1));

        assertThrows(
                ExpiredJwtException.class,
                () -> jwt.decode(tokenAsString));
    }

    @Test
    public void canNotTamperData() {

        String tokenAsString = jwt.encode(new TokenInfo("user", ""))
                .replaceFirst("\\.[^0]", ".0");

        assertThrows(
                SignatureException.class,
                () -> jwt.decode(tokenAsString));
    }
}
