package com.example.springsecurity;

import com.example.springsecurity.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
// import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
// import org.springframework.security.core.userdetails.User;
// import org.springframework.security.core.userdetails.UserDetails;
// import org.springframework.security.core.userdetails.UserDetailsService;
// import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
// import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
// import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.example.springsecurity.auth.ApplicationUserService;

import static com.example.springsecurity.ApplicationUserRole.*;
// import static com.example.springsecurity.ApplicationUserPermission.*;

// import java.util.concurrent.TimeUnit;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig {

    private final PasswordEncoder passwordEncoder;
    private final ApplicationUserService applicationUserService;

    @Autowired

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder, ApplicationUserService applicationUserService) {
        this.passwordEncoder = passwordEncoder;
        this.applicationUserService = applicationUserService;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // AuthenticationManager authenticationManager =
        // http.getSharedObject(AuthenticationConfigurationn.class);
        http
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                // .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                // .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(
                        authenticationManager(http.getSharedObject(AuthenticationConfiguration.class))))
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                // .antMatchers(HttpMethod.DELETE,
                // "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                // .antMatchers(HttpMethod.POST,
                // "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                // .antMatchers(HttpMethod.PUT,
                // "/management/api/**").hasAuthority(COURSE_WRITE.getPermission())
                // .antMatchers("/management/api/**").hasAnyRole(ADMIN.name(),
                // ADMIN_TRAINEE.name())
                .anyRequest()
                .authenticated();
        // .and()
        // // .httpBasic();
        // .formLogin()
        // .loginPage("/login").permitAll()
        // .defaultSuccessUrl("/courses", true)
        // .passwordParameter("password")
        // .usernameParameter("username")
        // .and()
        // .rememberMe()
        // .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
        // .key("somethingverysecured")
        // .rememberMeParameter("remember-me")
        // .and()
        // .logout()
        // .logoutUrl("/logout")
        // .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
        // .clearAuthentication(true)
        // .invalidateHttpSession(true)
        // .deleteCookies("JSESSIONID", "remember-me")
        // .logoutSuccessUrl("/login");

        return http.build();
    }

    // @Bean
    // protected UserDetailsService userDetailsService() {
    // UserDetails jimmyUser = User.builder()
    // .username("jimmy")
    // .password(passwordEncoder.encode("password"))
    // // .roles(STUDENT.name())
    // .authorities(STUDENT.getGrantedAuthorities())
    // .build();

    // UserDetails janeUser = User.builder()
    // .username("jane")
    // .password(passwordEncoder.encode("password123"))
    // // .roles(ADMIN.name())
    // .authorities(ADMIN.getGrantedAuthorities())
    // .build();

    // UserDetails tomUser = User.builder()
    // .username("tom")
    // .password(passwordEncoder.encode("password1234"))
    // // .roles(ADMIN_TRAINEE.name())
    // .authorities(ADMIN_TRAINEE.getGrantedAuthorities())
    // .build();

    // return new InMemoryUserDetailsManager(jimmyUser, janeUser, tomUser);
    // }

    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

}
