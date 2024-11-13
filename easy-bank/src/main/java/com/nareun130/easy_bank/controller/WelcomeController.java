package com.nareun130.easy_bank.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class WelcomeController {
    
    @GetMapping("/welcome")
    public String sayWelcome(){
        return "Welcome";
    }
}
