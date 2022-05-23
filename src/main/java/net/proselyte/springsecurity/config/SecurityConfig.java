package net.proselyte.springsecurity.config;

import net.proselyte.springsecurity.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/").permitAll()
                .anyRequest()
                .authenticated()
                .and()
                //теперь используем форму для логина
                .formLogin()
                //есть loginPage и она находится по ссылке "/auth/login"
                .loginPage("/auth/login").permitAll()
                //если всё хорошо, то мы перенаправляемся на страницу "/success"
                .defaultSuccessUrl("/success")
                .and()
                //настраиваем logout
                .logout()
                // use this first
                //.logoutUrl("/auth/logout")
                //logoutRequestMatcher должен быть обработан AntPathRequestMatcher-ом
                //logout должен проходить по ссылке "/auth/logout" и метод "POST"
                .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST"))
                .invalidateHttpSession(true)
                //очистим аутентификацию
                .clearAuthentication(true)
                //удалить куки с названием JSESSIONID
                .deleteCookies("JSESSIONID")
                //и потом должен быть перенаправлен на страницу (на метод контроллера) "/auth/login"
                .logoutSuccessUrl("/auth/login");
    }

    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder().username("admin")
                        .password(passwordEncoder().encode("admin"))
                        .authorities(Role.ADMIN.getAuthorities())
                        .build(),
                User.builder().username("user")
                        .password(passwordEncoder().encode("user"))
                        .authorities(Role.USER.getAuthorities())
                        .build()
        );
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
