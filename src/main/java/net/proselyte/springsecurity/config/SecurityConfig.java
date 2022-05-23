package net.proselyte.springsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
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
                .authorizeRequests()
                .antMatchers("/")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    /* Переопределяем метод userDetailsService() потому что хотим настроить
    * InMemoryUserDetailsManager, т.е. чтобы сохранялись имя и пароль пользователей в памяти
    * (пока работает приложение)*/
    @Bean
    @Override
    protected UserDetailsService userDetailsService() {
        //верни мне InMemoryUserDetailsManager
        return new InMemoryUserDetailsManager(
                //положи внутрь User
                User.builder()
                        //дай ему username=proselyte
                        .username("proselyte")
                        // Use without encode first
                        //Хранит пароли открытым текстом не стоит
                        //здесь шифруем пароль с помощью PasswordEncoder
                        //и размещаем это в памяти
                        .password(passwordEncoder().encode("proselyte"))
                        //пусть у него роль будет ADMIN
                        .roles("ADMIN")
                        .build()
        );
        // Go to UserDetailsServiceImpl - InMemory
    }

    /*Таким образом мы можем кодировать (шифровать) пароль с помощью PasswordEncoder,
    * это аналогично как шифруется на сайте https://bcrypt-generator.com/*/
    @Bean
    protected PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder(12);
    }
}
