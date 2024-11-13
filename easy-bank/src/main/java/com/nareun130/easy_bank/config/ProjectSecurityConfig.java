package com.nareun130.easy_bank.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defauSecurityFilterChain(HttpSecurity http) throws Exception {
        // 모든 요청은 보호, 허가, 거부 => 권한 x : 403
        // http.authorizeHttpRequests(requests ->
        // requests.anyRequest().authenticated());
        // http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
        // http.authorizeHttpRequests(requests -> requests.anyRequest().denyAll());
        http.authorizeHttpRequests(
                requests -> requests.requestMatchers("/myAccount", "/myBalance", "/myCards", "/myLoans").authenticated()
                        .requestMatchers("/notices", "/contact").permitAll());
        // 기본 폼 로그인
        http.formLogin(withDefaults());
        // * 기본 폼 로그인 비활성화
        // http.formLogin(flc -> flc.disable());//flc -> formLoginConfigurer
        // http basic 활성화 : username, password를 base64로 인코딩하여 header에 추가
        http.httpBasic(withDefaults());
        // http.httpBasic(hbc->hbc.disable());//hbc -> httpBasicConfigurer;
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails user = User.withUsername("user").password("{noop}12345").authorities("read").build();
        UserDetails admin = User.withUsername("admin").password("{noop}54321").authorities("admin").build();
        return new InMemoryUserDetailsManager(user, admin);
    }
}
