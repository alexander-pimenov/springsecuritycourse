package net.proselyte.springsecuritydemo.security;

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

/* Из этого класса создаем объект Фильтр JwtTokenFilter extends GenericFilterBean,
 * который будет пропускать запросы через себя (гетэвей)*/
@Component
public class JwtTokenFilter extends GenericFilterBean {
    private final JwtTokenProvider jwtTokenProvider;

    public JwtTokenFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /*Переопределяем метод doFilter.
     * */
    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        String token = jwtTokenProvider.resolveToken((HttpServletRequest) servletRequest);
        //проверяем токен
        try {
            if (token != null && jwtTokenProvider.validateToken(token)) {
                //и получаем объект Authentication
                Authentication authentication = jwtTokenProvider.getAuthentication(token);
                if (authentication != null) {
                    //если Authentication не null, то пусть SecurityContextHolder возьмет свой
                    //контекст и запихнет в него Authentication
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                }
            }
        } catch (JwtAuthenticationException e) {
            //если вдруг исключение, то SecurityContextHolder очисти свой контекст и в ответ пользователю запихнем ошибку
            SecurityContextHolder.clearContext();
            ((HttpServletResponse) servletResponse).sendError(e.getHttpStatus().value());
            //и для себя кинем новое сообщение ,чтоб его видели
            throw new JwtAuthenticationException("JWT token is expired or invalid");
        }
        //если всё нормально отработало и мы не поймали никаких исключений, то filterChain передай дальше
        //servletRequest и servletResponse
        filterChain.doFilter(servletRequest, servletResponse);
    }
}
