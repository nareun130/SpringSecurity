package com.nareun.easy_bank.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class LonasController {
    
    @GetMapping("/myLoans")
    public String getLoanDetails(){
        return "myBalance";
    }
}
