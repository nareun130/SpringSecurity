// package com.eazybytes.filter;

// import java.io.IOException;
// import java.nio.charset.StandardCharsets;

// import javax.crypto.SecretKey;
    // ~> KeyCloak에게 인증을 맡기기 위해 비활성화

// import org.springframework.core.env.Environment;
// import org.springframework.security.authentication.BadCredentialsException;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.core.Authentication;
// import org.springframework.security.core.authority.AuthorityUtils;
// import org.springframework.security.core.context.SecurityContextHolder;
// import org.springframework.web.filter.OncePerRequestFilter;

// import com.eazybytes.constants.ApplicationConstants;

// import io.jsonwebtoken.Claims;
// import io.jsonwebtoken.Jwts;
// import io.jsonwebtoken.security.Keys;
// import jakarta.servlet.FilterChain;
// import jakarta.servlet.ServletException;
// import jakarta.servlet.http.HttpServletRequest;
// import jakarta.servlet.http.HttpServletResponse;

// public class JWTTokenValidatorFilter extends OncePerRequestFilter {

//     @Override
//     protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
//             throws ServletException, IOException {
//         String jwt = request.getHeader(ApplicationConstants.JWT_HEADER);
//         if (jwt != null) {
//             try {
//                 Environment env = getEnvironment();
//                 if (env != null) {
//                     // * HS256일 때, 256bit보다 큰 secretKey를 필요
//                     String secret = env.getProperty(ApplicationConstants.JWT_SECRET,
//                             ApplicationConstants.JWT_SECRET_DEFAULT_VALUE);
//                     SecretKey secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
//                     if (secretKey != null) {
//                         Claims claims = Jwts.parser().verifyWith(secretKey).build().parseSignedClaims(jwt).getPayload();
//                         String username = String.valueOf(claims.get("username"));
//                         String authorities = String.valueOf(claims.get("authorities"));
//                         // * 생성되면서 isAuthenticated가 true로 설정됨.
//                         Authentication authentication = new UsernamePasswordAuthenticationToken(username, null,
//                                 AuthorityUtils.commaSeparatedStringToAuthorityList(authorities));
//                         SecurityContextHolder.getContext().setAuthentication(authentication);
//                     }
//                 }
//             } catch (Exception exception) {
//                 throw new BadCredentialsException("Invalid Token received!");
//             }
//         }
//         filterChain.doFilter(request, response);
//     }

//     @Override
//     protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
//         // * 로그인 중에는 호출되면 안되기 때문
//         return request.getServletPath().equals("/user");
//     }
// }
