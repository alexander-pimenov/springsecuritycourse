package net.proselyte.springsecuritydemo.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

/**
 * Разница между "Аутентификация" и "Авторизация", если говорить простыми словами:
 * <p>
 * Аутентификация (Authentication) — это «Ты кто?». Процесс проверки, что пользователь именно тот, за кого себя выдает.
 * Имеет ли это пользователь вообще доступ к нашей системе. Обычно это ввод логина и пароля.
 * Если у пользователя нет доступа к сиситеме, то получим "401 Unauthorized" (тут небольшая путаница в HTTP, но по сути — не залогинен).
 * <p>
 * Авторизация (Authorization) — это «Что тебе можно?».
 * Процесс проверки прав доступа: может ли этот пользователь читать, писать, удалять или заходить в конкретный раздел.
 * Если у пользователя нет прав на действие, то получим "403 Forbidden".
 * <p>
 * Главное - запомнить последовательность: сначала «Кто ты?», потом «Что тебе можно?».
 * <p>
 * Про аннотацию `@EnableWebSecurity`:<br>
 * - Включает веб-секьюрити в Spring <br>
 * - Активирует интеграцию с Spring MVC <br>
 * - Позволяет определять HTTP-правила безопасности (form login, URL-авторизация) <br>
 * - Без неё Spring Security не работает для веб-приложений <br>
 * Про аннотацию `@EnableGlobalMethodSecurity(prePostEnabled = true)`:<br>
 * - Включает аннотации уровня метода (@PreAuthorize, @PostAuthorize) <br>
 * - prePostEnabled = true — активирует именно @PreAuthorize, которые можем видеть в контроллере {@link net.proselyte.springsecuritydemo.rest.DeveloperRestControllerV1} <br>
 * - Без этой настройки аннотации @PreAuthorize в контроллере работать не будут! <br>
 * <p>
 * Порядок: сначала аутентификация → потом авторизация через @PreAuthorize.
 * <p>
 * JSESSIONID - при успешном логине создается сессия для конкретного пользователя, у неё будет идентификатор.
 * И в этой сессии пользователь может нормально работать. В каждом запросе в Request Headers будет передаваться в Cookie этот JSESSIONID.
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true) //эта аннотация удобнее и лаконичнее, чем добавлять .antMatchers(HttpMethod...) для каждого endpoint
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserDetailsService userDetailsService;

    @Autowired
    public SecurityConfig(@Qualifier("userDetailsServiceImpl") UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    /**
     * Настраивает правила доступа к HTTP-запросам, форму входа и выход из системы
     * (описывает все HTTP-правила: отключение CSRF, требование аутентификации, кастомный логин/логаут).
     *
     * <p>Конфигурация включает:
     * <ul>
     *   <li>Отключение CSRF-защиты (для упрощения разработки)</li>
     *   <li>Разрешение доступа к корню ({@code /}) без аутентификации</li>
     *   <li>Требование аутентификации для всех остальных запросов</li>
     *   <li>Кастомную страницу логина на {@code /auth/login} с перенаправлением на {@code /auth/success}</li>
     *   <li>Выход через POST на {@code /auth/logout} с инвалидацией сессии и удалением cookie {@code JSESSIONID}</li>
     * </ul>
     *
     * @param http объект для настройки HTTP-безопасности
     * @throws Exception если произошла ошибка при настройке
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/").permitAll() // пишем паттерн на какие url-ы кто имеет доступ; тут видим что в корень проекта имеет доступ кто угодно
                .anyRequest()
                .authenticated()    //говорим, что каждый запрос должен быть аутентифицирован
                .and()
                .formLogin()        // еще одна из форм Аутентификации, направляющая на форму логина.
                // Указываем кастомную страничку для ввода логипа/пароля. Она находится по ссылке /auth/login (эта же ссылка прописана в форме для ввода
                // логина/пароля) и все имеют доступ к этой странице (иначе получим ошибку).
                .loginPage("/auth/login").permitAll()
                // И если всё хорошо, то мы перенаправляемся на страницу /auth/success
                .defaultSuccessUrl("/auth/success")
                // ⚠️ Уточнение: "/auth/login" и "/auth/success" находятся в AuthController
                .and()
                // настроим свою страничку для logout, чтобы изенить дефолтный GET метод для него,
                // т.к. по документации GET это не безопасно использовать для logout
                .logout()
                // logoutRequestMatcher должен быть обработан с помощью AntPathRequestMatcher
                // logout должен проходить по ссылке "/auth/logout" и с методом POST
                // (в страничке success.html так же добавили кнопку для logout через метод POST)
                .logoutRequestMatcher(new AntPathRequestMatcher("/auth/logout", "POST"))
                .invalidateHttpSession(true) //при logout инвалидиоуем сессию
                .clearAuthentication(true)   // также чистим аутентификацию (это в JwtToken, который содержит детальную информацию кто я, откуда, зачем и для чего)
                .deleteCookies("JSESSIONID") //также удаляем куки под названием JSESSIONID
                .logoutSuccessUrl("/auth/login"); //и после этого перенаправить на страницу логина
    }

    /**
     * Регистрирует кастомный {@code DaoAuthenticationProvider} в {@code AuthenticationManager}.
     *
     * <p>По умолчанию Spring Security использует InMemory-аутентификацию.
     * Этот метод заменяет её на DAO-провайдер, который проверяет логин и пароль
     * по данным из базы данных через {@link #daoAuthenticationProvider()}
     * (этот метод заменяет дефолтный InMemory-провайдер на DAO-провайдер с БД).
     *
     * @param auth билдер для настройки механизмов аутентификации
     * @throws Exception если произошла ошибка при настройке
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //говорим, что провайдер будет не стандартный - InMemory, а DAO провайдер.
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    /**
     * Для кодирования данных.
     *
     * @return объект passwordEncoder с закодировнными данными.
     */
    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12); // 12 - для алгоритма кодирования
    }

    /**
     * Создаёт и настраивает провайдер аутентификации, проверяющий логин и пароль по данным из БД.
     *
     * <p>Связывает два компонента:
     * <ul>
     *   <li>{@code UserDetailsService} — загружает пользователя из БД по email</li>
     *   <li>{@code PasswordEncoder} — сравнивает введённый пароль с хешем в базе через BCrypt</li>
     * </ul>
     *
     * <p>При каждом входе Spring Security делегирует проверку этому провайдеру:
     * он загружает {@code UserDetails}, берёт его пароль, расшифровывает хеш и сверяет
     * с введённым пользователем. Если совпадает — аутентификация успешна.
     *
     * <p>Зачем нужен DaoAuthenticationProvider:<br>
     * Это «движок» аутентификации. Когда пользователь вводит логин и пароль, Spring Security
     * вызывает этот бин, и он делает три шага:<br>
     * 1. Берёт email из формы логина <br>
     * 2. Передаёт его в ваш UserDetailsService — тот идёт в БД и возвращает UserDetails
     * (с хешированным паролем и правами) <br>
     * 3. Берёт PasswordEncoder и сравнивает введённый пароль с хешем из БД через BCrypt <br>
     *
     * <p>Без этого бина Spring Security не знал бы, откуда брать пользователей и как проверять пароли —
     * по умолчанию он использует InMemory-хранилище. Мы же заменяем его на DB-ориентированный провайдер.
     *
     * @return настроенный {@code DaoAuthenticationProvider}
     */
    @Bean
    protected DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(userDetailsService);
        return daoAuthenticationProvider;
    }
}
