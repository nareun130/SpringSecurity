package com.nareun130.easy_bank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
// @EnableJpaRepositories("com.nareun130.easy_bank.repository")
// @EntityScan("com.nareun130.easy_bank.model")
// * @EnableWebSecurity -> SpringBoot에서는 선택사항, SpringMVC에서는 필수
public class EasyBankApplication {

	public static void main(String[] args) {
		SpringApplication.run(EasyBankApplication.class, args);
	}

}
