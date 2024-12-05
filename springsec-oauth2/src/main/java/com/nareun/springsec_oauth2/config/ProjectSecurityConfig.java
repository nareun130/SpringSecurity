package com.nareun.springsec_oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class ProjectSecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity.authorizeHttpRequests(requests -> requests.requestMatchers("/secure").authenticated()
                .anyRequest().permitAll())
                .formLogin(Customizer.withDefaults())
                // * OAUTH2 로그인 활성화 -> 자체 인증 서버를 사용하는지, 소셜로그인 인증 서버를 사용하는지 명시!
                .oauth2Login(Customizer.withDefaults());
        return httpSecurity.build();
    }

    // @Bean
    // ClientRegistrationRepository clientRegistrationRepository() {

    //     ClientRegistration github = githubClientRegistration();
    //     ClientRegistration facebook = facebookClientRegistration();
    //     // * 대부분 InMemoryClientRegistrationRepository를 사용 -> 인증 관련 세부 정보가 필요
    //     return new InMemoryClientRegistrationRepository(github, facebook);
    // }

    // private ClientRegistration githubClientRegistration() {
    //     // * 등록 id를 이용해 GITHUB의 세부정보가 InMemoryClientRegistrationRepository안에 저장됨.
    //     // * 작명은 사용자 마음
    //     return CommonOAuth2Provider.GITHUB.getBuilder("github")
    //             // * clientId,clientSecret은 깃헙에서 받아야 함.
    //             .clientId("Ov23liEzRvfGCfDoGsNm")
    //             .clientSecret("23c90ad4dc8348054ec23ed3aee98ebe54267825")
    //             .build();
    // }

    // private ClientRegistration facebookClientRegistration() {
    //     return CommonOAuth2Provider.FACEBOOK.getBuilder("facebook")
    //             .clientId("590108183699670")
    //             .clientSecret("e88de70535a6af2e2b7a70c57bb009aa")
    //             .build();
    // }
}
