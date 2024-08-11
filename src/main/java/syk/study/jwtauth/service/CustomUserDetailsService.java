package syk.study.jwtauth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import syk.study.jwtauth.entity.UserEntity;
import syk.study.jwtauth.repository.UserRepository;


// UserDetailsService : 인증을 요구한 회원의 정보를 받아 db 에서 찾은 뒤 UserDetails 객체를 전달한다.

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity userEntity = userRepository.findByUsername(username);

        if (userEntity != null) {
            return userEntity; // AuthenticationManager 에서 검증함
        }

        return null;
    }
}
