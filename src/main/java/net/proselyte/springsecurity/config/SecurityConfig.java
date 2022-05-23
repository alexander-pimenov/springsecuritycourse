package net.proselyte.springsecurity.config;

import net.proselyte.springsecurity.model.Role;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /* Реализуем доступ разграниченный по ролям.
     * Используем свою конфигурацию.
     * Аутентификация - это проверка друг ты или враг, т.е. имеем ли пользователь
     * право на доступ к приложению вообще.
     * Авторизация - это к каким страницам (ресурсам) пользователь имеет доступ.
     * */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                /*включаем механизм от csrf угрозы (межсайтовые запросы)*/
                .csrf().disable()
                //авторизуем запросы след.обр.
                .authorizeRequests()
                /* antMatchers - сущность, которая указывает на какие паттерны url, кто имеет доступ
                 * "/" - в корень проекта имеет доступ кто угодно*/
                .antMatchers("/").permitAll()
                /* "/api/**" - на этот url (/api/** - и всё что угодно после /api) должны иметь доступ только
                 * пользователи с определенными ролями.
                 * Если пользователь идет с методом GET (т.е. чтение), то это или ADMIN, или USER*/
                .antMatchers(HttpMethod.GET, "/api/**").hasAnyRole(Role.ADMIN.name(), Role.USER.name())
                /* Если пользователь идет с методом POST (т.е. запись), то это только ADMIN */
                .antMatchers(HttpMethod.POST, "/api/**").hasRole(Role.ADMIN.name())
                /* Если пользователь идет с методом DELETE, то это только ADMIN */
                .antMatchers(HttpMethod.DELETE, "/api/**").hasRole(Role.ADMIN.name())
                /* так мы говорим, что КАЖДЫЙ запрос должен быть аутентифицирован: .anyRequest().authenticated()*/
                .anyRequest()
                .authenticated()
                /* И используем httpBasic(), т.е. base64*/
                .and()
                .httpBasic();
    }

    /* Переопределяем метод userDetailsService() потому что хотим настроить
     * InMemoryUserDetailsManager, т.е. чтобы сохранялись имя и пароль пользователей в памяти
     * (пока работает приложение)
     * Добавим в систему два пользователя admin:admin и user:user*/
    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        //верни мне InMemoryUserDetailsManager
        return new InMemoryUserDetailsManager(
                //положи внутрь User
                User.builder()
                        //дай ему username=admin
                        .username("admin")
                        // Use without encode first
                        //Хранит пароли открытым текстом не стоит
                        //здесь шифруем пароль с помощью PasswordEncoder
                        //и размещаем это в памяти
                        .password(passwordEncoder().encode("admin"))
                        //пусть у него роль будет ADMIN
                        .roles(Role.ADMIN.name())
                        .build(),
                //положи внутрь еще одного User
                User.builder().username("user")
                        // Use without encode first
                        .password(passwordEncoder().encode("user"))
                        //пусть у него роль будет USER
                        .roles(Role.USER.name())
                        .build()
        );
        // Go to UserDetailsServiceImpl - InMemory
    }

    /*Таким образом мы можем кодировать (шифровать) пароль с помощью PasswordEncoder,
     * это аналогично как шифруется на сайте https://bcrypt-generator.com/*/
    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
