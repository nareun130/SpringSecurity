package com.nareun130.easy_bank.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

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
        // 평문으로 비밀번호 저장
        // UserDetails user =
        // User.withUsername("user").password("{noop}12345").authorities("read").build();
        // UserDetails admin =
        // User.withUsername("admin").password("{noop}54321").authorities("admin").build();
        UserDetails user = User.withUsername("user").password("{noop}nareun@130").authorities("read").build();
        UserDetails admin = User.withUsername("admin").password("{bcrpyt}$2a$12$GwUegjvGui0qbn.8yW7q9OVI1Eg4I5BvvNCCSeEIBZYOTgULEPOMq").authorities("admin").build();
        return new InMemoryUserDetailsManager(user, admin);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // return new BCryptPasswordEncoder();
        // * 기본적으로 BCryptPasswordEncoder 이용
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    //spring security 6.3부터 가능
    //* CompromisedPasswordChecker : 비밀번호가 데이터 유출 사고에 노출된 적 있는지 확인하는 기능
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();//~> 실패 시 403 에러
    }
}
