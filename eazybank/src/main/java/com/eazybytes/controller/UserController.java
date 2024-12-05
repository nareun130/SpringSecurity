package com.eazybytes.controller;

import java.util.Optional;

import org.springframework.core.env.Environment;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.eazybytes.model.Customer;
import com.eazybytes.repository.CustomerRepository;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class UserController {

    private final CustomerRepository customerRepository;
    // ~> KeyCloak에게 인증을 맡기기 위해 비활성화
    // private final PasswordEncoder passwordEncoder;
    // private final AuthenticationManager authenticationManager;
    // private final Environment env;

    // ~> KeyCloak에게 인증을 맡기기 위해 비활성화
    // @PostMapping("/register")
    // public ResponseEntity<String> registerUser(@RequestBody Customer customer) {
    //     try {
    //         String hashPwd = passwordEncoder.encode(customer.getPwd());
    //         customer.setPwd(hashPwd);
    //         customer.setCreateDt(new Date(System.currentTimeMillis()));
    //         Customer savedCustomer = customerRepository.save(customer);

    //         if (savedCustomer.getId() > 0) {
    //             return ResponseEntity.status(HttpStatus.CREATED).body("Given user details are successfully registered");
    //         } else {
    //             return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User registration failed");
    //         }
    //     } catch (Exception ex) {
    //         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
    //                 .body("An exception occurred: " + ex.getMessage());
    //     }
    // }

    @RequestMapping("/user")
    public Customer getUserDetailsAfterLogin(Authentication authentication) {
        Optional<Customer> optionalCustomer = customerRepository.findByEmail(authentication.getName());
        return optionalCustomer.orElse(null);
    }

    // ~> KeyCloak에게 인증을 맡기기 위해 비활성화
    // @PostMapping("/apiLogin")
    // public ResponseEntity<LoginResponseDTO> apiLogin(@RequestBody LoginRequestDTO loginRequest) {
    //     String jwt = "";
    //     Authentication authentication = UsernamePasswordAuthenticationToken.unauthenticated(loginRequest.username(),
    //             loginRequest.password());
    //     Authentication authenticationResponse = authenticationManager.authenticate(authentication);
    //     if (authenticationResponse != null && authenticationResponse.isAuthenticated()) {
    //         if (env != null) {
    //             // * HS256일 때, 256bit보다 큰 secretKey를 필요
    //             String secret = env.getProperty(ApplicationConstants.JWT_SECRET,
    //                     ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
    //             SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    //             jwt = Jwts.builder().issuer("Eazy Bank").subject("JWT Token")
    //                     .claim("username", authenticationResponse.getName())
    //                     .claim("authorities", authenticationResponse.getAuthorities().stream().map(
    //                             GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
    //                     .issuedAt(new Date())
    //                     // * 약 8시간 설정 */
    //                     .expiration(new Date((new Date()).getTime() + 30000000))
    //                     .signWith(secretKey).compact();
    //         }
    //     }
    //     return ResponseEntity.status(HttpStatus.OK).header(ApplicationConstants.JWT_HEADER, jwt)
    //             .body(new LoginResponseDTO(HttpStatus.OK.getReasonPhrase(), jwt));
    // }

}
