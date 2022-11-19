package com.studyLogAuth.LogAuth;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude={ SecurityAutoConfiguration.class })
public class LogAuthApplication {

	public static void main(String[] args) {
		SpringApplication.run(LogAuthApplication.class, args);
	}

}
