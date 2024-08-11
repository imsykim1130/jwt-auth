package syk.study.jwtauth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StreamUtils;
import syk.study.jwtauth.dto.LoginDto;
import syk.study.jwtauth.jwt.JwtUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Iterator;

@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    // DI
    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest req, HttpServletResponse res) throws AuthenticationException {
        // 요청에서 사용자 정보 추출(form 형태로 받을 때)
//        String username = req.getParameter("username");
//        String password = req.getParameter("password");

        // 요청에서 사용자 정보 추출(json 형태로 받을 때)
        LoginDto loginDto;

        try {
            ObjectMapper objectMapper = new ObjectMapper();
            ServletInputStream inputStream = req.getInputStream();
            String messageBody = StreamUtils.copyToString(inputStream, StandardCharsets.UTF_8);
            loginDto = objectMapper.readValue(messageBody, LoginDto.class);
            System.out.println("사용자 정보 추출");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        String username = loginDto.getUsername();
        String password = loginDto.getPassword();
        System.out.println("username: " + username);
        System.out.println("password: " + password);


        // 검증을 위한 토큰 생성
        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password, null);

        // 토큰 전달
        System.out.println("인증정보 전달");
        return authenticationManager.authenticate(token);
    }
    // 인증 성공 시 실행됨
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication auth) throws IOException, ServletException {
        // 인증 성공 시 Authentication 객체에서 유저의 정보를 추출하여
        // JWT 토큰 생성한다.
        UserDetails userDetails = (UserDetails) auth.getPrincipal();
        String username = userDetails.getUsername();
        Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority grantedAuthority = iterator.next();
        String role = grantedAuthority.getAuthority();
        String token = jwtUtil.createJwt(username, role, 60*60*100L);

        // 만든 토큰을 response 헤더에 넣어준다.
        // http 인증 방식은 인증 헤더의 형태가 정해져 있다.
        // [인증방식] [인증 토큰 string] -> 여기서는 Bearer 인증방식을 사용했다.
        response.addHeader("Authorization", "Bearer " + token);

        System.out.println("successful authentication");

    }
    // 인증 실패 시 실행됨
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        response.setStatus(401);
        System.out.println("unsuccessful authentication");
    }

}
