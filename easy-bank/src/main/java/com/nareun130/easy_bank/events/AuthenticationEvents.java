package com.nareun130.easy_bank.events;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class AuthenticationEvents {
    //~> 따로 설정해줄 필요 x -> SpringBoot에서 EventListener를 지우 ㅓㄴ 
    @EventListener
    public void onSuccess(AuthenticationSuccessEvent successEvent){
        log.info("Login successful for user {}", successEvent.getAuthentication().getName());
    }

    @EventListener
    public void onFailure(AbstractAuthenticationFailureEvent failureEvent){
        log.error("Login failed for user : {} due to : {}", failureEvent.getAuthentication().getName(),failureEvent.getException().getMessage());
    }
}
