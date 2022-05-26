package net.proselyte.springsecuritydemo.security;

import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

/* В этом классе конфигурируем токен аутентификацию.
 * В SecurityConfigurerAdapter используем дефолтную цепочку секьюрити DefaultSecurityFilterChain
 * и HttpSecurity configure*/
@Component
public class JwtConfigurer extends SecurityConfigurerAdapter<DefaultSecurityFilterChain, HttpSecurity> {
    private final JwtTokenFilter jwtTokenFilter;

    public JwtConfigurer(JwtTokenFilter jwtTokenFilter) {
        this.jwtTokenFilter = jwtTokenFilter;
    }

    /*Переопределяем метод */
    @Override
    public void configure(HttpSecurity httpSecurity) {
        /* httpSecurity добавь в самое начало jwtTokenFilter */
        httpSecurity.addFilterBefore(jwtTokenFilter, UsernamePasswordAuthenticationFilter.class);
    }
}
