package net.proselyte.springsecuritydemo.rest;

import lombok.extern.slf4j.Slf4j;
import net.proselyte.springsecuritydemo.model.User;
import net.proselyte.springsecuritydemo.repository.UserRepository;
import net.proselyte.springsecuritydemo.security.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.HashMap;
import java.util.Map;

/**
 * REST-контроллер для аутентификации пользователей через JWT.
 * Предоставляет endpoint для входа (получение токена) и выхода.
 */
@Slf4j
@RestController
@RequestMapping("/api/v1/auth")
public class AuthenticationRestControllerV1 {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthenticationRestControllerV1(AuthenticationManager authenticationManager, UserRepository userRepository, JwtTokenProvider jwtTokenProvider) {
        this.authenticationManager = authenticationManager;
        this.userRepository = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * Аутентифицирует пользователя по email и паролю.
     * При успехе возвращает JWT-токен и email пользователя.
     *
     * @param request DTO с email и паролем
     * @return ResponseEntity с email и токеном (200) или ошибкой (403)
     */
    @PostMapping("/login")
    public ResponseEntity<?> authenticate(@RequestBody AuthenticationRequestDTO request) {
        log.info("Login attempt for email: {}", request.getEmail());
        try {
            String email = request.getEmail();
            String password = request.getPassword();
            //Аутентифицируем пользователя на основании email и password.
            //AuthenticationManager аутентифицируй мне пользователя с помощью UsernamePasswordAuthenticationToken,
            //передав в него email и password, то есть нужно нам получить аутентификацию на основании email и password.
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(email, password));
            //Достаем пользователя из БД нашей системы, чтобы получить его роль.
            User user = userRepository.findByEmail(email).orElseThrow(() -> new UsernameNotFoundException("User '%s' doesn't exists".formatted(email)));
            //Создаем токен на основании email и роли пользователя.
            String token = jwtTokenProvider.createToken(email, user.getRole().name());
            log.info("User '{}' authenticated successfully, JWT token generated", email);
            //Если всё нашли и создали токен, то готовим ответ:
            Map<Object, Object> response = new HashMap<>();
            response.put("email", email);
            response.put("token", token);
            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            log.warn("Authentication failed for email '{}': {}", request.getEmail(), e.getMessage());
            return new ResponseEntity<>("Invalid email/password combination", HttpStatus.FORBIDDEN);
        }
    }

    /**
     * Завершает сессию пользователя — очищает SecurityContextHolder.
     *
     * @param request  HTTP-запрос
     * @param response HTTP-ответ
     */
    @PostMapping("/logout")
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        log.info("Logout request received");
        SecurityContextLogoutHandler securityContextLogoutHandler = new SecurityContextLogoutHandler();
        securityContextLogoutHandler.logout(request, response, null);
    }
}
