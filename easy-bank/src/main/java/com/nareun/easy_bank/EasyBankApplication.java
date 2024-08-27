package com.nareun.easy_bank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

@SpringBootApplication
//@EnableWebSecurity(debug = true) // 선택 사항 -> security filter chain을 로깅하기 위해
@EnableMethodSecurity(prePostEnabled = true, securedEnabled = true, jsr250Enabled = true)
public class EasyBankApplication {

	public static void main(String[] args) {
		SpringApplication.run(EasyBankApplication.class, args);
	}

}