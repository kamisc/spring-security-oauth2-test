package com.sewerynkamil.springsecurityoauth2;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import java.util.Arrays;

@Configuration
public class SpringSecurityConfigNew {
    @Bean
    public PasswordEncoder getBCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
        UserDetails user = User.withUsername("user")
                .password(getBCryptPasswordEncoder().encode("user1234"))
                .roles("USER")
                .build();

        UserDetails admin = User.withUsername("admin")
                .password(getBCryptPasswordEncoder().encode("admin1234"))
                .roles("USER", "ADMIN")
                .build();

        return new InMemoryUserDetailsManager(Arrays.asList(user, admin));
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests((auth) ->
                auth
                .antMatchers("/for-user").hasAnyRole("USER", "ADMIN")
                .antMatchers("/for-admin").hasAnyRole("ADMIN"))
                .formLogin(AbstractAuthenticationFilterConfigurer::permitAll)
                .logout()
//                .deleteCookies("Cookies")
                .logoutSuccessUrl("/bye").permitAll();

        return http.build();
    }
}
