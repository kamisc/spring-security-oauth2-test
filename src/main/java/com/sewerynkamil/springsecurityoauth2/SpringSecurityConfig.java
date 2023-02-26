package com.sewerynkamil.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Collections;

@Configuration
public class SpringSecurityConfig extends WebSecurityConfigurerAdapter {

    @Bean
    public PasswordEncoder getBCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        User user = new User(
                "user",
                getBCryptPasswordEncoder().encode("user1234"),
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")));

        User admin = new User(
                "admin",
                getBCryptPasswordEncoder().encode("admin1234"),
                Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN")));

        auth.inMemoryAuthentication().withUser(user).withUser(admin);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/for-user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/for-admin").hasAnyRole("ADMIN")
                .and()
                .formLogin().permitAll()
                .and()
                .logout().logoutUrl("/bye");
    }
}
