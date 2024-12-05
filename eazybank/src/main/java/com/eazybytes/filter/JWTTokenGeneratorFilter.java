// package com.eazybytes.filter;

// import java.io.IOException;
// import java.nio.charset.StandardCharsets;
// import java.util.Date;
// import java.util.stream.Collectors;

// import javax.crypto.SecretKey;

// import org.springframework.core.env.Environment;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.GrantedAuthority;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.web.filter.OncePerRequestFilter;

// import com.eazybytes.constants.ApplicationConstants;
    // ~> KeyCloak에게 인증을 맡기기 위해 비활성화

// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.security.Keys;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// public class JWTTokenGeneratorFilter extends OncePerRequestFilter {

//     @Override
//     protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//             throws ServletException, IOException {
//         Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//         if (authentication != null) {
//             // * GenericFilterBean을 통해 환경변수를 읽어옴.
//             Environment env = getEnvironment();
//             if (env != null) {
//                 // * HS256일 때, 256bit보다 큰 secretKey를 필요
//                 String secret = env.getProperty(ApplicationConstants.JWT_SECRET,
//                         ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
//                 SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
//                 String jwt = Jwts.builder().issuer("Eazy Bank").subject("JWT Token")
//                         .claim("username", authentication.getName())
//                         .claim("authorities", authentication.getAuthorities().stream().map(
//                                 GrantedAuthority::getAuthority).collect(Collectors.joining(",")))
//                         .issuedAt(new Date())
//                         // * 약 8시간 설정 */
//                         .expiration(new Date((new Date()).getTime() + 30000000))
//                         .signWith(secretKey).compact();
//                 response.setHeader(ApplicationConstants.JWT_HEADER, jwt);
//             }
//         }
//         filterChain.doFilter(request, response);
//     }

//     @Override
//     protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {

//         // * true일 때 필터 실행 x
//         return !request.getServletPath().equals("/user");
//     }

// }
