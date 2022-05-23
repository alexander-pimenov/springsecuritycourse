package net.proselyte.springsecurity.config;

import net.proselyte.springsecurity.model.Permission;
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

/*Доступ основанный на ролях удобен, но не настолько гибок как хотелось бы.
 * Можно создавать роли и давать им права (на запись, на чтение), так будет гибче.
 * Для этого используется такое понятие, как permissions
 * Например, на чтение имеют доступ те, которые имеют permissions = developers:read,
 * а на запись, те которые имеют permissions = developers:write.
 * Доступ мы настраиваем для permission, а не для ролей, как было в предыдущем STEP4
 *
 * Также можно настраивать Authority с помощью аннотаций прямо из контроллера.
 * Смотри STEP6*/
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    /*Перепишем наш метод, чтобы работать не с РОЛЯМИ, а с Authority и PERMISSION.
     * Используем свою конфигурацию.
     * Аутентификация - это проверка друг ты или враг, т.е. имеем ли пользователь
     * право на доступ к приложению вообще.
     * Авторизация - это к каким страницам (ресурсам) пользователь имеет доступ.*/
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
                 * пользователи с определенными permissions.
                 * Если пользователь идет с методом GET (т.е. чтение), то это разрешение Permission.DEVELOPERS_READ*/
                .antMatchers(HttpMethod.GET, "/api/**").hasAuthority(Permission.DEVELOPERS_READ.getPermission())
                /* Если пользователь идет с методом POST (т.е. запись), то это только Permission.DEVELOPERS_WRITE */
                .antMatchers(HttpMethod.POST, "/api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermission())
                /* Если пользователь идет с методом POST (т.е. запись), то это только Permission.DEVELOPERS_WRITE */
                .antMatchers(HttpMethod.DELETE, "/api/**").hasAuthority(Permission.DEVELOPERS_WRITE.getPermission())
                /* так мы говорим, что КАЖДЫЙ запрос должен быть аутентифицирован: .anyRequest().authenticated()*/
                .anyRequest()
                .authenticated()
                .and()
                /* И используем httpBasic(), т.е. base64*/
                .httpBasic();
    }

    /* Переопределяем метод userDetailsService() потому что хотим настроить
     * InMemoryUserDetailsManager, т.е. чтобы сохранялись имя и пароль пользователей в памяти
     * (пока работает приложение)
     * Добавим в систему два пользователя admin:admin и user:user
     * Но уже им дадим не РОЛИ, как в STEP4, а authorities*/
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
                        //пусть у него authorities будет ADMIN
                        .authorities(Role.ADMIN.getAuthorities())
                        .build(),
                User.builder().username("user")
                        .password(passwordEncoder().encode("user"))
                        .authorities(Role.USER.getAuthorities())
                        .build()
        );
    }

    /*Таким образом мы можем кодировать (шифровать) пароль с помощью PasswordEncoder,
     * это аналогично как шифруется на сайте https://bcrypt-generator.com/*/
    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
