package net.proselyte.springsecuritydemo.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.test.util.ReflectionTestUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private UserDetailsService userDetailsService;

    @BeforeEach
    void setUp() {
        jwtTokenProvider = new JwtTokenProvider(userDetailsService);
        ReflectionTestUtils.setField(jwtTokenProvider, "secretKey", "testSecret");
        ReflectionTestUtils.setField(jwtTokenProvider, "authorizationHeader", "Authorization");
        ReflectionTestUtils.setField(jwtTokenProvider, "validityInMilliseconds", 3600L);
        jwtTokenProvider.init();
    }

    @Test
    void createToken_shouldReturnValidJwt() {
        String token = jwtTokenProvider.createToken("user@test.com", "USER");

        assertNotNull(token);
        assertTrue(token.split("\\.").length == 3);

        String username = Jwts.parser()
                .setSigningKey(Base64.getEncoder().encodeToString("testSecret".getBytes()))
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
        assertEquals("user@test.com", username);
    }

    @Test
    void createToken_shouldContainRoleInClaims() {
        String token = jwtTokenProvider.createToken("admin@test.com", "ADMIN");

        String role = Jwts.parser()
                .setSigningKey(Base64.getEncoder().encodeToString("testSecret".getBytes()))
                .parseClaimsJws(token)
                .getBody()
                .get("role", String.class);
        assertEquals("ADMIN", role);
    }

    @Test
    void validateToken_shouldReturnTrueForValidToken() {
        String token = jwtTokenProvider.createToken("user@test.com", "USER");

        assertTrue(jwtTokenProvider.validateToken(token));
    }

    @Test
    void validateToken_shouldThrowExceptionForExpiredToken() {
        String secret = Base64.getEncoder().encodeToString("testSecret".getBytes());
        String expiredToken = Jwts.builder()
                .setSubject("user@test.com")
                .setIssuedAt(new Date(System.currentTimeMillis() - 10000))
                .setExpiration(new Date(System.currentTimeMillis() - 5000))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();

        assertThrows(JwtAuthenticationException.class,
                () -> jwtTokenProvider.validateToken(expiredToken));
    }

    @Test
    void validateToken_shouldThrowExceptionForInvalidSignature() {
        String secret = Base64.getEncoder().encodeToString("wrongSecret".getBytes());
        String tamperedToken = Jwts.builder()
                .setSubject("user@test.com")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 3600000))
                .signWith(SignatureAlgorithm.HS256, secret)
                .compact();

        assertThrows(JwtAuthenticationException.class,
                () -> jwtTokenProvider.validateToken(tamperedToken));
    }

    @Test
    void validateToken_shouldThrowExceptionForMalformedToken() {
        assertThrows(JwtAuthenticationException.class,
                () -> jwtTokenProvider.validateToken("malformed.token.value"));
    }

    @Test
    void getUsername_shouldReturnSubjectFromToken() {
        String token = jwtTokenProvider.createToken("user@test.com", "USER");

        String username = jwtTokenProvider.getUsername(token);

        assertEquals("user@test.com", username);
    }

    @Test
    void resolveToken_shouldExtractFromHeader() {
        HttpServletRequest request = org.mockito.Mockito.mock(HttpServletRequest.class);
        org.mockito.Mockito.when(request.getHeader("Authorization")).thenReturn("myJwtToken");

        String token = jwtTokenProvider.resolveToken(request);

        assertEquals("myJwtToken", token);
    }

    @Test
    void resolveToken_shouldReturnNullWhenHeaderMissing() {
        HttpServletRequest request = org.mockito.Mockito.mock(HttpServletRequest.class);
        org.mockito.Mockito.when(request.getHeader("Authorization")).thenReturn(null);

        String token = jwtTokenProvider.resolveToken(request);

        assertNull(token);
    }
}
