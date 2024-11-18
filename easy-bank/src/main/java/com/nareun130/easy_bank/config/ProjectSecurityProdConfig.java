package com.nareun130.easy_bank.config;

import static org.springframework.security.config.Customizer.withDefaults;

import javax.sql.DataSource;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.authentication.password.CompromisedPasswordChecker;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.password.HaveIBeenPwnedRestApiPasswordChecker;

import com.nareun130.easy_bank.exceptionhadling.CustomBasicAuthenticationEntryPoint;

@Configuration
@Profile("prod")
public class ProjectSecurityProdConfig {

    @Bean
    SecurityFilterChain defauSecurityFilterChain(HttpSecurity http) throws Exception {
        // 모든 요청은 보호, 허가, 거부 => 권한 x : 403
        // http.authorizeHttpRequests(requests ->
        // requests.anyRequest().authenticated());
        // http.authorizeHttpRequests(requests -> requests.anyRequest().permitAll());
        // http.authorizeHttpRequests(requests -> requests.anyRequest().denyAll());
        // * csrf 비활성화 : 기본적으로 POST,PUT,DELETE에 대해 Security가 보호
        http.requiresChannel(rcc -> rcc.anyRequest().requiresSecure())// https만 허용
            .csrf(csrfConfig -> csrfConfig.disable())
                .authorizeHttpRequests(
                        requests -> requests.requestMatchers("/myAccount", "/myBalance", "/myCards", "/myLoans")
                                .authenticated()
                                .requestMatchers("/notices", "/contact", "/register").permitAll());
        // 기본 폼 로그인
        http.formLogin(withDefaults());
        // * 기본 폼 로그인 비활성화
        // http.formLogin(flc -> flc.disable());//flc -> formLoginConfigurer
        // http basic 활성화 : username, password를 base64로 인코딩하여 header에 추가
        // http.httpBasic(withDefaults());
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        // http.httpBasic(hbc->hbc.disable());//hbc -> httpBasicConfigurer;
        return http.build();
    }

    // * 커스텀 UserDetailsService를 구현 하였기에 필요 x
    // @Bean
    // public UserDetailsService userDetailsService(DataSource dataSource) {
    // return new JdbcUserDetailsManager(dataSource);
    // }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // return new BCryptPasswordEncoder();
        // * 기본적으로 BCryptPasswordEncoder 이용
        // ! BcryptPasswordEncoder를 직접 사용 x -> DelegatingPasswordEncoder를 사용할 것! 표준이
        // 바뀌었을 때를 대비
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    // spring security 6.3부터 가능
    // * CompromisedPasswordChecker : 비밀번호가 데이터 유출 사고에 노출된 적 있는지 확인하는 기능
    @Bean
    public CompromisedPasswordChecker compromisedPasswordChecker() {
        return new HaveIBeenPwnedRestApiPasswordChecker();// ~> 실패 시 403 에러
    }
}
