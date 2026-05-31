package net.proselyte.springsecuritydemo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.GenericFilterBean;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Фильтр, который перехватывает каждый HTTP-запрос, извлекает JWT-токен
 * из заголовка, проверяет его валидность и устанавливает аутентификацию
 * в SecurityContext.
 */
@Slf4j
@Component
public class JwtTokenFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * Обрабатывает входящий запрос: извлекает токен, валидирует его и,
     * если токен корректен, устанавливает аутентификацию в {@link SecurityContextHolder}.
     * При невалидном токене очищает контекст и возвращает ошибку.
     * <p>
     * Здесь мы видим приведение типов (casting) и это фраза компилятору:<br>
     * «Я знаю, что этот объект на самом деле является более конкретным типом. Поверь мне и дай доступ к его методам».<br>
     * У {@link ServletRequest} нет метода getHeader() — он объявлен только в {@link HttpServletRequest}. Но переменная servletRequest
     * физически указывает на объект класса {@link org.apache.catalina.connector.RequestFacade} (или аналогичный),
     * который реализует {@link HttpServletRequest}. Каст просто меняет "угол зрения" на тот же объект.<br>
     * Без каста код бы не скомпилировался — компилятор видит только общий тип {@link ServletRequest} и не знает про
     * HTTP-методы, хотя объект под капотом всегда HTTP.
     *
     * @param servletRequest  входящий запрос
     * @param servletResponse ответ
     * @param filterChain     цепочка фильтров для передачи запроса дальше
     */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) servletRequest);
        log.info("Processing request, token present: {}", token != null);
        try {
            if (token != null && jwtTokenProvider.validateToken(token)) {
                Authentication authentication = jwtTokenProvider.getAuthentication(token);
                if (authentication != null) {
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                    log.info("Authentication set for user: {}", authentication.getName());
                }
            }
        } catch (JwtAuthenticationException e) {
            log.warn("JWT authentication failed: {}", e.getMessage());
            SecurityContextHolder.clearContext();
            ((HttpServletResponse) servletResponse).sendError(e.getHttpStatus().value());
            throw new JwtAuthenticationException("JWT token is expired or invalid");
        }
        filterChain.doFilter(servletRequest, servletResponse);  // для передачи запроса дальше
    }
}

//Потому что сигнатура doFilter от Filter принимает общие типы ServletRequest/ServletResponse (не привязанные к HTTP). А методы resolveToken() и sendError() есть только у HTTP-версий — HttpServletRequest и HttpServletResponse. Приведение в данном случае безопасно — внутри веб-приложения это всегда HTTP-запрос/ответ.
