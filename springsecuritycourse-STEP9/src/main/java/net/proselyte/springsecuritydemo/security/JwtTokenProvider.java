package net.proselyte.springsecuritydemo.security;

import io.jsonwebtoken.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;
import java.util.Base64;
import java.util.Date;

/**
 * Провайдер для работы с JWT-токенами.
 * Предоставляет методы для создания, валидации и парсинга JWT,
 * а также для извлечения токена из HTTP-запроса.
 * Токены подписываются алгоритмом HS256 с секретным ключом,
 * который кодируется в Base64 при инициализации.
 */
@Slf4j
@Component
public class JwtTokenProvider {

    private final UserDetailsService userDetailsService;

    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.header}")
    private String authorizationHeader;
    @Value("${jwt.expiration}")
    private long validityInMilliseconds;

    /**
     *
     * @param userDetailsService инжектим в конструктор нашу реализация интерфейса {@link UserDetailsService} - {@link UserDetailsServiceImpl}
     */
    public JwtTokenProvider(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Инициализирует секретный ключ для подписи JWT.
     * Кодирует строковый secretKey в Base64 - это необходимо, чтобы ключ
     * можно было использовать с алгоритмом HS256.
     * Метод вызывается автоматически после создания бина благодаря @PostConstruct.
     */
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
        log.info("JwtTokenProvider initialized, secret key encoded in Base64");
    }

    /**
     * Создаёт JWT-токен для аутентифицированного пользователя.
     * В claims токена записывается username (subject) и роль пользователя.
     * Токен подписывается алгоритмом HS256 с использованием секретного ключа.
     * <p>
     * Claims в JWT — это просто данные (поля) внутри токена, которые ты хочешь передать.<br>
     * Представь, что JWT-токен — это наклейка на пропуск. <b>Claims</b> — это то, что на ней написано:<br>
     * имя, должность, дата выдачи.<br>
     * Сервер читает эту наклейку и сразу понимает, кто ты и что тебе можно, без похода в базу.<br>
     * В коде в методе:<br>
     * - setSubject(username) — claim "кто я"<br>
     * - put("role", role) — claim "моя роль" (кастомное поле)<br>
     * Три стандартных claims — sub (subject), iat (issued at), exp (expiration) — как раз и задаются через setClaims,
     * setIssuedAt, setExpiration. Всё остальное — твои собственные.
     * <p>
     *
     * @param username имя пользователя (будет установлено как subject токена)
     * @param role     роль пользователя (добавляется в кастомное поле "role")
     * @return сгенерированный JWT-токен в виде строки
     */
    public String createToken(String username, String role) {
        log.info("Creating JWT token for user: {} with role: {}", username, role);
        Claims claims = Jwts.claims().setSubject(username); //claim "кто я"
        claims.put("role", role); //claim "моя роль" (кастомное поле)
        Date now = new Date();
        Date validity = new Date(now.getTime() + validityInMilliseconds * 1000);

        String token = Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now) //время создания токена
                .setExpiration(validity) //время когда токен перестает быть валидным
                .signWith(SignatureAlgorithm.HS256, secretKey) //алгоритм + секретный ключ
                .compact();
        log.info("JWT token created successfully for user: {}", username);
        return token;
    }

    /**
     * Проверяет, что JWT-токен корректен: подпись совпадает с секретным ключом,
     * срок действия токена не истёк.
     *
     * @param token JWT-токен в виде строки
     * @return true, если токен валиден и не просрочен
     * @throws JwtAuthenticationException если токен недействителен или истёк
     */
    public boolean validateToken(String token) {
        log.info("Validating JWT token");
        try {
            Jws<Claims> claimsJws = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            boolean valid = !claimsJws.getBody().getExpiration().before(new Date());
            log.info("JWT token validation result: {}", valid);
            return valid;
        } catch (JwtException | IllegalArgumentException e) {
            log.warn("JWT token validation failed: {}", e.getMessage());
            throw new JwtAuthenticationException("JWT token is expired or invalid", HttpStatus.UNAUTHORIZED);
        }
    }

    /**
     * Извлекает из токена username, загружает пользователя через {@link UserDetailsService}
     * и возвращает объект {@link Authentication} для Spring Security.
     *
     * @param token JWT-токен
     * @return объект {@link Authentication} с данными пользователя и его ролями
     */
    public Authentication getAuthentication(String token) {
        String username = getUsername(token);
        log.info("Getting authentication for user: {}", username);
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
    }

    /**
     * Извлекает имя пользователя (subject) из JWT-токена.
     *
     * @param token JWT-токен
     * @return username, который был указан при создании токена
     */
    public String getUsername(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    /**
     * Достаёт JWT-токен из HTTP-запроса по заголовку авторизации.
     *
     * @param request входящий HTTP-запрос
     * @return строка токена из заголовка или null, если заголовок отсутствует
     */
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader(authorizationHeader);
    }
}
