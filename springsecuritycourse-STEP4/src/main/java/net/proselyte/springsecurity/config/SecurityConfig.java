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
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()  //механизм от csrf угрозы ("Межсайтовая подделка запроса")
                .authorizeRequests()
                .antMatchers("/").permitAll()
                // ⚠️ Уточнение: если  унас будет 50 ролей, то их нужно вписать сюда.
                .antMatchers(HttpMethod.GET, "/api/**").hasAnyRole(Role.ADMIN.name(), Role.USER.name()) //на этот API чтения может иметь доступ пользователь с ролями ADMIN и USER, и ADMIN, и USER могут читать
                .antMatchers(HttpMethod.POST, "/api/**").hasRole(Role.ADMIN.name()) //на этот API записи может иметь доступ пользователь с ролями ADMIN, только ADMIN может создавать
                .antMatchers(HttpMethod.DELETE, "/api/**").hasRole(Role.ADMIN.name()) //на этот API удаления может иметь доступ пользователь с ролями ADMIN, только ADMIN может удалять
                .anyRequest()
                .authenticated()  //говорим, что каждый запрос должен быть аутентифицирован
                // ⚠️ Уточнение: "каждый запрос, не подпадающий под правила выше, требует аутентификации"
                // То есть если ты добавишь еще эндпоинты, кроме "/" и "/api/**" - их тоже проверят
                .and()
                .httpBasic();  // клиент сам передает заголовок Authorization, это самый простой способ аутентификации в HTTP
    }

    /**
     * Метод для добавления пользоваетелей в систему.
     *
     * @return
     */
    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder().username("admin")  //строим пользователя admin
                        // Use without encode first
                        .password(passwordEncoder().encode("admin"))
                        .roles(Role.ADMIN.name())
                        .build(),
                User.builder().username("user")  //строим пользователя user
                        // Use without encode first
                        .password(passwordEncoder().encode("user"))
                        .roles(Role.USER.name())
                        .build()
        );
        // Go to UserDetailsServiceImpl - InMemory
    }

    @Bean
    protected PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }
}
