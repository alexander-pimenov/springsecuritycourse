package net.proselyte.springsecuritydemo.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

/**
 * Конфигуратор, который подключает JwtTokenFilter к цепочке фильтров Spring Security.
 * Фильтр вставляется перед UsernamePasswordAuthenticationFilter, чтобы JWT-аутентификация
 * выполнялась до стандартной form-login.
 */
@Slf4j
@Component
public class JwtConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final JwtTokenFilter jwtTokenFilter;

    public JwtConfigurer(JwtTokenFilter jwtTokenFilter) {
        this.jwtTokenFilter = jwtTokenFilter;
    }

    /**
     * Переопределяет метод, который в {@link SecurityConfigurerAdapter} имеет пустую реализацию.
     * Этот наш метод добавляет наш {@link JwtTokenFilter} в цепочку фильтров HTTP Security
     * перед фильтром {@link UsernamePasswordAuthenticationFilter}.
     *
     * @param httpSecurity объект конфигурации HTTP Security
     */
    @Override
    public void configure(HttpSecurity httpSecurity) {
        log.info("Applying JwtConfigurer: adding JwtTokenFilter before UsernamePasswordAuthenticationFilter");
        httpSecurity.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
