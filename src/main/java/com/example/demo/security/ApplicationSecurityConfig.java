package com.example.demo.security;

import com.example.demo.auth.ApplicationUserService;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.concurrent.TimeUnit;

import static com.example.demo.security.ApplicationUserRole.*;
import static com.example.demo.security.ApplicationUserPermission.*;

//  git checkout 6-Form_Based_Authentication

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
// TODO эта аннотация добавляется для переноса всех пермишенов из .antMatchers этого класса в аннотации
// TODO @PreAuthorize класса StudentManagementController
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired
    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    // первый вариант

    /*
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }
    */

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                //TODO 6) важное добавление -  в начале выключено, потом заредактирываем и включаем CSRF token для теста
                .csrf().disable()
//                .csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
//                .and()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name()) // TODO только студенты могут заходить по данному пути

                // TODO 1) те по этому пути удалять, изменять, брать, регать может только тот кто  имеет разрешение (permission) - редактировать (писать) COURSE
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.name())

                // TODO 4) изменения в авторизации - меняем .name() на .getPermission()
                // TODO 5) убераем описание от сюда и переносим его в аннотации в StudentManagementController
//                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
//                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())

                // TODO 3) метод GET может вызвать или ADMIN или ADMINTRAINIEE
                // TODO 5) убераем описание от сюда и переносим его в аннотации в StudentManagementController
//                .antMatchers(HttpMethod.GET, "/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())

                // TODO 2) ограничиваем доступ - доступно по этому пути только только для ADMIN and ADMINTRAINEE -
                // TODO убираем, тк задействуем это ограничение в HttpMethod.GET
                //.antMatchers("/management/api/**").hasAnyRole(ADMIN.name(), ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()

                // TODO 6) включение BASE_AUTIFICATION
//                .httpBasic();

                // TODO кастомизация странички login
                // TODO добавляем в pom - spring-boot-starter-thymeleaf
                .formLogin()
                    .loginPage("/login")
                    .permitAll()
                //TODO пишем перенаправление - редирект на страницу courses в случае верного введения логина и пароля
                    .defaultSuccessUrl("/courses",true)
                //TODO доп параметры, можно и без них, которые должны совпадать с html
                    .passwordParameter("password")
                    .usernameParameter("username")
                .and()
                .rememberMe()
                    .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
                    .key("somethingverysecured")
                    .rememberMeParameter("remember-me")
                //TODO доп параметры, можно и без них, которые должны совпадать с html
                .and()
                .logout()
                    .logoutUrl("/logout")
                    .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                // TODO 8) если убрать .csrf().disable() - то эту строку тоже нужно убрать
                // TODO выставляем http метод для logout - GET, но в случае .csrf().disable() можем выставить любой
                    .clearAuthentication(true)
                    .invalidateHttpSession(true)
                    .deleteCookies("JSESSIONID", "remember-me")
                    .logoutSuccessUrl("/login");
                // TODO 7) прописываем действие если выходим по logout - удаление из кукис JSESSIONID и значения  remember-me тк
                // TODO они сохнаянются на 30 мин
    }
    // TODO улучшение кода - появился класс FakeApplicationDaoService и ApplicationUserDao
/*
    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        UserDetails annaSmithUser = User.builder()
                .username("annasmith")
                .password(passwordEncoder.encode("password"))
//                .roles(STUDENT.name()) //ROLE_STUDENT
                // TODO улучшение кода
                .authorities(STUDENT.getGrantedAuthorities())
                .build();

        UserDetails lindaUser = User.builder()
                .username("linda")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMIN.name()) //ROLE_ADMIN
                // TODO улучшение кода
                .authorities(ADMIN.getGrantedAuthorities())
                .build();

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password123"))
//                .roles(ADMINTRAINEE.name()) //ROLE_ADMINTRAINEE
                // TODO улучшение кода
                .authorities(ADMINTRAINEE.getGrantedAuthorities())
                .build();

        return new InMemoryUserDetailsManager(
                annaSmithUser,
                lindaUser,
                tomUser
        );
    }
 */

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }
}
