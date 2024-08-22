package com.nareun.easy_bank.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterchain(HttpSecurity http) throws Exception {
        http.csrf((csrf) -> csrf.disable())
                .authorizeHttpRequests(
                        reuqests -> reuqests.requestMatchers("/myAccount", "/myBalance", "myLoans",
                                        "/myCards").authenticated()
                                .requestMatchers("/notices", "/contact", "/register").permitAll())
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

    //* 인메모리 방식 -> 운영 환경 x
//    @Bean
//    public InMemoryUserDetailsManager userDetailsService() {
//        UserDetails admin = User.withDefaultPasswordEncoder()
//                .username("admin")
//                .password("12345")
//                .authorities("admin")
//                .build();
//        UserDetails user = User.withDefaultPasswordEncoder()
//                .username("user")
//                .password("12345")
//                .authorities("read")
//                .build();
//        return new InMemoryUserDetailsManager(admin, user);
//    }

    /*
     * UserDetailsService를 구현한 Bean이 2개 이므로
     * No AuthenticationProvider found for
     * org.springframework.security.authentication.UsernamePasswordAuthenticationToken 발생
     */

//    @Bean
//    public UserDetailsService userDetailsService(DataSource dataSource) {
//        //* UserDetailsService를 UserDetailsManager가 상속 이것을 JdbcUserDetailsManager가 상속
//        return new JdbcUserDetailsManager(dataSource);
//    }

    @Bean
    public PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
        return new BCryptPasswordEncoder();
    }

}
