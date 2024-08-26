package com.nareun.easy_bank.config;

import com.nareun.easy_bank.filter.AUthoritiesLoggingAfterFilter;
import com.nareun.easy_bank.filter.AuthoritiesLoggingAtFilter;
import com.nareun.easy_bank.filter.CsrfCookieFilter;
import com.nareun.easy_bank.filter.RequestValidationBeforeFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.sql.DataSource;
import java.util.Collections;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        //* CsrfTokenRequestHandler구현을 위함
        //* csrf토큰이 요청 속성으로써 활성화 될 수 있도록 도와주고 헤더로든 변수로든 토큰 값을 해결함.
        //~> Spring Security가 csrf토큰을 생성하고 값이 처리되거나 UI앱에게 헤더 또는 쿠키의 값을 전달하기 위해서 구현해야 함.
        CsrfTokenRequestAttributeHandler requestHandler = new CsrfTokenRequestAttributeHandler();
        requestHandler.setCsrfRequestAttributeName("_csrf");

        http
                // * SecurityContextHolder안에 있는 인증 정보를 저장하는 역할을 맡지 않겠다는 걸 의미 -> 프레임워크들이 대신 수행 하도록
                //~> 기본 true : 보안 컨텍스트 명시적 저장
                //~> false : 보안 컨텍스트 자동 저장 -> 변경이 생겨도 자동으로 반영 -> 대부분의 app에서 사용
                .securityContext(context -> context.requireExplicitSave(false))
                // * 첫 로그인이 성공하면 항상 JSESSIONID를 생성하도록 -> 매번 자격증명을 하지 않기 하기 위해
                // ~> 모든 요청에 대해 새로운 세션이 생기거나, 기존 세션이 있으면 사용
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.ALWAYS))
                .cors(cors -> cors.configurationSource(request -> {
                    // & CORS는 보안정책, CSRF는 보안 위협
                    //* 이 CORS정보들이 pre-flight request의 응답으로 간다.
                    CorsConfiguration config = new CorsConfiguration();
                    config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                    config.setAllowedMethods(Collections.singletonList("*"));
                    //* 인증정보들을 넘기고 받는 데에 동의
                    config.setAllowCredentials(true);
                    config.setAllowedHeaders(Collections.singletonList("*"));
                    //* 브라우저에게 이 설정을 1시간 동안 기억해두었다가 maxAge가 지나면 캐시로 저장하게 함.
                    config.setMaxAge(3600L);
                    return config;
                }))
                //! 절대 csrf보호를 비활성화 시키면 안됨!!
                //~> csrf보호가 필요 없는 경우에도 설정은 필요!
//                .csrf(csrf -> csrf.disable())
                //* 이렇게 특정 경로만 csrf비활성화 가능 -> 완전한 해결책 x
//                .csrf(csrf -> csrf.ignoringRequestMatchers("/contact", "/register"))
                .csrf(csrf -> csrf.csrfTokenRequestHandler(requestHandler).ignoringRequestMatchers("/contact", "/register")
                        //* CookieCsrfTokenRepository : csrf토큰을 쿠키로 유지하는 역할 -> Header에서 "X-XSRF-Token"이라는 이름을 찾음.
                        //* withHttpOnlyFalse()를 적용해서 ui app에서 Cookie를 읽어낼 수 있도록
                        //~> csrf토큰을 보내기 위해 Filter가 필요!! -> CsrfCookieFilter
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                //* BasicAuthenticationFilter 다음에 CsrfCookieFilter 실행 -> 로그인 동작 후 csrf토큰 생성
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                //* BasicAuthenticationFilter전에 필터 추가
                .addFilterBefore(new RequestValidationBeforeFilter(), BasicAuthenticationFilter.class)
                .addFilterAfter(new AUthoritiesLoggingAfterFilter(),BasicAuthenticationFilter.class)
                .addFilterAt(new AuthoritiesLoggingAtFilter(),BasicAuthenticationFilter.class)
                .authorizeHttpRequests(
                        auth -> auth
                                // * 권한
//                                .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
//                                .requestMatchers("/myBalance").hasAnyAuthority("VIEWACCOUNT", "VIEWBALANCE")
//                                .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
//                                .requestMatchers("/myCards").hasAuthority("VIEWCARD")
                                // * 역할 -> DB에는 ROLE_ADMIN이런 식으로 접두사를 붙이지만 역할 사용시에는 붙이지 않는다!
                                .requestMatchers("/myAccount").hasRole("USER")
                                .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                                .requestMatchers("/myLoans").hasRole("USER")
                                .requestMatchers("/myCards").hasRole("MANAGER")

                                .requestMatchers("/user").authenticated()
                                .requestMatchers("/notices", "/contact", "/register").permitAll())
                .formLogin(Customizer.withDefaults())
                .httpBasic(Customizer.withDefaults());

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
//        return NoOpPasswordEncoder.getInstance();
        return new BCryptPasswordEncoder();
    }

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

}
