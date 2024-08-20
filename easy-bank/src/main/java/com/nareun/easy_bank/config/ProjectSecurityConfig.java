package com.nareun.easy_bank.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterchain(HttpSecurity http) throws Exception {
        // * 특정 URL에 대한 Filter
        // http.authorizeHttpRequests(
        // reuqests -> reuqests.requestMatchers("/myAccount", "/myBalance", "myLoans",
        // "/myCards").authenticated()
        // .requestMatchers("/notices", "/contact").permitAll())
        // .formLogin(Customizer.withDefaults())
        // .httpBasic(Customizer.withDefaults());
        // return http.build();

        // * 모든 요청을 거부
        // ~> 인증은 성공 했지만 인가에서 막음.
        // http.authorizeHttpRequests(reuqests -> reuqests.anyRequest().denyAll())
        // .formLogin(Customizer.withDefaults())
        // .httpBasic(Customizer.withDefaults());
        // return http.build();

        // * 모든 요청 허용
        http.authorizeHttpRequests(reuqests -> reuqests.anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());
        return http.build();
    }
}
