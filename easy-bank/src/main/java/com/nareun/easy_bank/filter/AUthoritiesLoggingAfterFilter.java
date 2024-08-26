package com.nareun.easy_bank.filter;

import jakarta.servlet.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import java.io.IOException;
import java.util.logging.Logger;

public class AUthoritiesLoggingAfterFilter implements Filter {

    private final Logger LOG = Logger.getLogger(AUthoritiesLoggingAfterFilter.class.getName());

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {

        //* 현재 인증된 유저의 세부 정보를 인증 객체의 형태로 가져옴.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        // 인증 성공 여부
        if (null != authentication) {
            LOG.info("User" + authentication.getName() + "is successfully authenticated and "
                    + "has the authorities" + authentication.getAuthorities().toString());
        }
        chain.doFilter(request, response);
    }
}
