package com.eazybytes.config;

import static org.springframework.security.config.Customizer.withDefaults;

import java.util.Arrays;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import com.eazybytes.exceptionhandling.CustomAccessDeniedHandler;
import com.eazybytes.exceptionhandling.CustomBasicAuthenticationEntryPoint;
import com.eazybytes.filter.CsrfCookieFilter;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
@Profile("!prod")
public class ProjectSecurityConfig {

    // @Value("${spring.security.oauth2.resourceserver.opaquetoken.introspection-uri}")
    // String introspectionUri;

    // @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-id}")
    // String clientId;

    // @Value("${spring.security.oauth2.resourceserver.opaquetoken.client-secret}")
    // String clientSecret;

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new KeyCloakRoleConverter());
        CsrfTokenRequestAttributeHandler csrfTokenRequestAttributeHandler = new CsrfTokenRequestAttributeHandler();
        http
                // * jwt사용 : SecurityContext에 인증 저장 x
                // .securityContext(contextConfig -> contextConfig.requireExplicitSave(false))
                // * jwt사용 : 무상태로 만든다. -> jsessionId생성 x
                .sessionManagement(
                        sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .cors(corsConfig -> corsConfig
                        .configurationSource(new CorsConfigurationSource() {
                            @Override
                            public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {
                                CorsConfiguration config = new CorsConfiguration();
                                config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
                                config.setAllowedMethods(Collections.singletonList("*"));
                                config.setAllowCredentials(true);
                                // * 다른 곳으로 부터 받는 헤더
                                config.setAllowedHeaders(Collections.singletonList("*"));
                                // * 백엔드에서 응답에 노출 시킬 헤더
                                config.setExposedHeaders(Arrays.asList("Authorization"));
                                config.setMaxAge(3600L);
                                return config;
                            }
                        }))
                .csrf(csrfConfig -> csrfConfig
                        .csrfTokenRequestHandler(csrfTokenRequestAttributeHandler)
                        .ignoringRequestMatchers("/register", "/contact"
                        // ,"/apiLogin"
                        )
                        .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()))
                // * JWT를 통해 stateles하므로 csrf 비활성화
                // .csrf(csrfConfig -> csrfConfig.disable())
                // ~> KeyCloak에게 인증을 맡기기 위해 Csrf만 놔두고, JWT 비활성화
                .addFilterAfter(new CsrfCookieFilter(), BasicAuthenticationFilter.class)
                // .addFilterBefore(new RequestValidationBeforeFilter(),
                // BasicAuthenticationFilter.class)
                // .addFilterAfter(new AuthoritiesLoggingAfterFilter(),
                // BasicAuthenticationFilter.class)
                // .addFilterAt(new AuthoritiesLoggingAtFilter(),
                // BasicAuthenticationFilter.class)
                // * 로그인 후 jwt 생성
                // .addFilterAfter(new JWTTokenGeneratorFilter(),
                // BasicAuthenticationFilter.class)
                // * jwt 검증 성공하면 다시 인증하지 않도록 하기 위해
                // .addFilterBefore(new JWTTokenValidatorFilter(),
                // BasicAuthenticationFilter.class)
                .requiresChannel(rcc -> rcc.anyRequest().requiresInsecure()) // Only HTTP
                .authorizeHttpRequests((requests) -> requests
                        // .requestMatchers("/myAccount").hasAuthority("VIEWACCOUNT")
                        // .requestMatchers("/myBalance").hasAnyAuthority("VIEWBALANCE","VIEWACCOUNT")
                        // .requestMatchers("/myLoans").hasAuthority("VIEWLOANS")
                        // .requestMatchers("/myCards").hasAuthority("VIEWCARDS")
                        .requestMatchers("/myAccount").hasRole("USER")
                        .requestMatchers("/myBalance").hasAnyRole("USER", "ADMIN")
                        // .requestMatchers("/myLoans").hasRole("USER")
                        .requestMatchers("/myLoans").authenticated()
                        .requestMatchers("/myCards").hasRole("USER")
                        .requestMatchers("/user").authenticated()
                        .requestMatchers("/notices", "/contact", "/error", "/register"
                        // , "/invalidSession", "/apiLogin"
                        )
                        .permitAll());
        // ~> KeyCloak에게 인증을 맡기기 위해 비활성화
        // http.formLogin(withDefaults());
        // * 리소스 서버로 jwt를 받기 위해 추가
        http.oauth2ResourceServer(
                rsc -> rsc.jwt(jwtConfigurer -> jwtConfigurer.jwtAuthenticationConverter(jwtAuthenticationConverter)));
        // * 리소스 서버로 opaque token을 받기 위해 추가
        // http.oauth2ResourceServer(
        // rsc -> rsc.opaqueToken(otc -> otc.authenticationConverter(new
        // KeycloakOpaqueRoleConverter())
        // .introspectionUri(this.introspectionUri)
        // .introspectionClientCredentials(this.clientId, this.clientSecret)));
        http.httpBasic(hbc -> hbc.authenticationEntryPoint(new CustomBasicAuthenticationEntryPoint()));
        http.exceptionHandling(ehc -> ehc.accessDeniedHandler(new CustomAccessDeniedHandler()));
        return http.build();
    }
    // ~> KeyCloak에게 인증을 맡기기 위해 비활성화

    // @Bean
    // public PasswordEncoder passwordEncoder() {
    // return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    // }

    /**
     * From Spring Security 6.3 version
     *
     * @return
     */
    // @Bean
    // public CompromisedPasswordChecker compromisedPasswordChecker() {
    // return new HaveIBeenPwnedRestApiPasswordChecker();
    // }
    // @Bean
    // public AuthenticationManager authenticationManager(UserDetailsService
    // userDetailsService,
    // PasswordEncoder passwordEncoder) {
    // EazyBankProdUsernamePwdAuthenticationProvider authenticationProvider = new
    // EazyBankProdUsernamePwdAuthenticationProvider(
    // userDetailsService, passwordEncoder);
    // ProviderManager providerManager = new
    // ProviderManager(authenticationProvider);
    // // * Authentication내부의 비밀번호 지우지 않도록, 기본 값은 true
    // //* -> 비즈니스 로직 내에서 유효성 검사를 위해 비밀번호가 필요할 수 있으니 false*/
    // providerManager.setEraseCredentialsAfterAuthentication(false);
    // return providerManager;
    // }

}
