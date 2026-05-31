package net.proselyte.springsecuritydemo.config;

import lombok.extern.slf4j.Slf4j;
import net.proselyte.springsecuritydemo.rest.AuthenticationRestControllerV1;
import net.proselyte.springsecuritydemo.security.JwtConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Конфигурация Spring Security для JWT-аутентификации.
 * Отключает CSRF, устанавливает STATELESS-сессии (токен не хранится на сервере),
 * разрешает доступ к / и /api/v1/auth/login без аутентификации, все остальные
 * запросы требуют JWT-токена.
 */
@Slf4j
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //эта аннотация удобнее и лаконичнее, чем добавлять .antMatchers(HttpMethod...) для каждого endpoint
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final JwtConfigurer jwtConfigurer;

    public SecurityConfig(JwtConfigurer jwtConfigurer) {
        this.jwtConfigurer = jwtConfigurer;
    }

    /**
     * Настраивает HTTP Security:
     * <ul>
     *   <li>отключает CSRF (JWT-токены не требуют защиты от CSRF)</li>
     *   <li>устанавливает STATELESS-режим сессий (токен не хранится на сервере)</li>
     *   <li>разрешает доступ к / и /api/v1/auth/login без токена</li>
     *   <li>все остальные запросы требуют аутентификации</li>
     *   <li>подключает {@link JwtConfigurer} для проверки JWT-токенов</li>
     * </ul>
     *
     * @param http объект конфигурации HTTP Security
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        log.info("Configuring HTTP Security: CSRF disabled, STATELESS sessions, JWT auth");
        http
                .csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .antMatchers("/api/v1/auth/login").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .apply(jwtConfigurer);
    }

    /**
     * Создаёт бин AuthenticationManager, необходимый для аутентификации
     * в {@link AuthenticationRestControllerV1}. Без этого контроллер не получит этот бин.
     *
     * @return бин AuthenticationManager
     */
    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        //используем стандартный AuthenticationManager из родительского класса WebSecurityConfigurerAdapter
        return super.authenticationManagerBean();
    }

    /**
     * Создаёт бин PasswordEncoder с алгоритмом BCrypt и силой 12.
     *
     * @return бин PasswordEncoder
     */
    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
