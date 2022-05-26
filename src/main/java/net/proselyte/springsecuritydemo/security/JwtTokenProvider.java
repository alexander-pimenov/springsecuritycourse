package net.proselyte.springsecuritydemo.security;

import io.jsonwebtoken.*;
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

/*Класс для получения JWT токена. Он компонент, т.к.
мы хотим с ним работать из Спрингового контекста.
* Объект этого класса генерирует JWT токен.*/
@Component
public class JwtTokenProvider {

    /*Аутентификация хранится в контексте и её можно получить с помощью UserDetailsService*/
    private final UserDetailsService userDetailsService;

    @Value("${jwt.secret}")
    private String secretKey;
    @Value("${jwt.header}")
    private String authorizationHeader;
    @Value("${jwt.expiration}")
    private long validityInMilliseconds;

    public JwtTokenProvider(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /*Для безопасности переопределяем метод init, чтобы до начала работы приложения нам
     * зашифровали в строку наш secretKey*/
    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    /*Метод для создания токена по передаваемым кредам - username, role*/
    public String createToken(String username, String role) {
        /*Claims - Набор утверждений JWT.
         * В конечном счете, это карта JSON, и к ней можно добавлять любые значения,
         * но для удобства стандартные имена JWT предоставляются как безопасные для
         * типов геттеры и сеттеры.
         * Поскольку этот интерфейс расширяет Map&lt;String, Object&gt;, если вы хотите
         * добавить свои собственные свойства, вы просто используете методы карты.
         * Claims - это мапа, в которую мы накидываем наши кастомные поля, которые нам необходимы.*/
        Claims claims = Jwts.claims().setSubject(username);
        claims.put("role", role);
        //указываем когда токен создан IssuedAt
        Date now = new Date();
        //указываем когда токен будет завершен Expiration (обычно имя validity)
        Date validity = new Date(now.getTime() + validityInMilliseconds * 1000); //*1000, чтобы получить секунды

        //строим токен
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now) //когда токен создан
                .setExpiration(validity) //когда токен заикспайрится
                .signWith(SignatureAlgorithm.HS256, secretKey) //подписали с помощью алгоритма и секретного ключа
                .compact();
    }

    /*Нужно уметь валидировать токен, т.е. убедиться что токен корректен*/
    public boolean validateToken(String token) {
        try {
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(secretKey) //устанавливаем секретный ключ
                    .parseClaimsJws(token); //парсим клеимсы из токена
            //проверяем, что не истек наш Expiration Date
            return !claimsJws.getBody().getExpiration().before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new JwtAuthenticationException("JWT token is expired or invalid", HttpStatus.UNAUTHORIZED);
        }
    }

    /*Некий утильный метод для получения объекта Authentication из токена.
    * Для этого используем UserDetailsService*/
    public Authentication getAuthentication(String token) {
        UserDetails userDetails = this.userDetailsService.loadUserByUsername(getUsername(token));
        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
        //Здесь креды пустые - "". И нужны права пользователя userDetails.getAuthorities()
    }

    /*Некий утильный метод для получения username из токена*/
    public String getUsername(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey) //устанавливаем секретный ключ
                .parseClaimsJws(token)//парсим клеимсы из токена
                .getBody()//берем клеим
                .getSubject(); //берем его имя
    }

    /*Метод для контроллера. Для получения токена из нашего запроса.*/
    public String resolveToken(HttpServletRequest request) {
        return request.getHeader(authorizationHeader);
    }
}
