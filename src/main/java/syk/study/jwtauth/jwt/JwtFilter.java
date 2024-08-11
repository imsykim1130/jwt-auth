package syk.study.jwtauth.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;
import syk.study.jwtauth.entity.UserEntity;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 요청에서 토큰 추출
        String authorization = request.getHeader("Authorization");

        // 헤더 검증 로직
        if(authorization == null || !authorization.startsWith("Bearer ")) {
            System.out.println("token null");
            filterChain.doFilter(request, response);
            return; // 반드시 필요
        }

        // 순수 토큰 추출
        String token = authorization.substring(7);
        System.out.println(token);

        // 토큰 소멸시간 검증 로직
        if(jwtUtil.isTokenExpired(token)) {
            System.out.println("token expired");
            filterChain.doFilter(request, response);
            return;
        }

        // 모든 검증 만족할 시 토큰 정보를 통해 Authentication 객체 만들고 SecurityContextHolder 에 강제 주입(세션에 사용자 등록)
        // 해당 세션은 stateless 하게 관리되기 때문에 해당 요청이 끝나면 소멸된다.
        String username = jwtUtil.getUsername(token);
        String role = jwtUtil.getRole(token);

        UserDetails userDetails = UserEntity.builder().username(username).role(role).build();
        Authentication authentication = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(authentication);
        System.out.println("토큰 발행");
        filterChain.doFilter(request, response);
    }
}
