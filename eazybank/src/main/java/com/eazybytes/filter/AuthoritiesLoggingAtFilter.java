// package com.eazybytes.filter;
// ~> KeyCloak에게 인증을 맡기기 위해 비활성화

// import java.io.IOException;

// import jakarta.servlet.Filter;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.ServletRequest;
// import jakarta.servlet.ServletResponse;
// import lombok.extern.slf4j.Slf4j;

// @Slf4j
// public class AuthoritiesLoggingAtFilter implements Filter {

// @Override
// public void doFilter(ServletRequest request, ServletResponse response,
// FilterChain chain)
// throws IOException, ServletException {
// log.info("Authentication is in progress...");
// chain.doFilter(request, response);
// }

// }
