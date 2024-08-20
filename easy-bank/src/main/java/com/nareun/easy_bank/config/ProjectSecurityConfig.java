package com.nareun.easy_bank.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterchain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(
                reuqests -> reuqests.requestMatchers("/myAccount", "/myBalance", "myLoans",
                        "/myCards").authenticated()
                        .requestMatchers("/notices", "/contact").permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();

        // * 2개다 운영 환경 x
        // 1. 모든 요청을 거부
        // ~> 인증은 성공 했지만 인가에서 막음.
        // http.authorizeHttpRequests(reuqests -> reuqests.anyRequest().denyAll())
        // .formLogin(Customizer.withDefaults())
        // .httpBasic(Customizer.withDefaults());
        // return http.build();

        // 2. 모든 요청 허용
        // http.authorizeHttpRequests(reuqests -> reuqests.anyRequest().permitAll())
        // .formLogin(Customizer.withDefaults())
        // .httpBasic(Customizer.withDefaults());
        // return http.build();
    }

    @Bean
    public InMemoryUserDetailsManager userDetailsService() {
        UserDetails admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("12345")
                .authorities("admin")
                .build();
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("12345")
                .authorities("read")
                .build();
        return new InMemoryUserDetailsManager(admin, user);
    }
}
