//package com.nareun.easy_bank.config;
//
//import com.nareun.easy_bank.model.Customer;
//import com.nareun.easy_bank.repository.CustomerRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.security.core.GrantedAuthority;
//import org.springframework.security.core.authority.SimpleGrantedAuthority;
//import org.springframework.security.core.userdetails.User;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.security.core.userdetails.UsernameNotFoundException;
//import org.springframework.stereotype.Service;
//
//import java.util.ArrayList;
//import java.util.List;
//

//! AuthenticationProvider의 구현으로 필요 없어짐!
//@Service
//public class EasyBankUserDetails implements UserDetailsService {
//
//    @Autowired
//    CustomerRepository customerRepository;
//
//    @Override
//    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
//
//        String userName, password = null;
//        List<GrantedAuthority> authorities = null;
//        List<Customer> customers = customerRepository.findByEmail(username);
//        if (customers.size() == 0) {
//            throw new UsernameNotFoundException("User details not found for the user: " + username);
//        } else {
//            userName = customers.get(0).getEmail();
//            password = customers.get(0).getPwd();
//            authorities = new ArrayList<>();
//            authorities.add(new SimpleGrantedAuthority(customers.get(0).getRole()));
//        }
//        //* 이 값을 DaoAuthenticationProvider가 받는다.
//        return new User(userName, password, authorities);
//
//    }
//}




