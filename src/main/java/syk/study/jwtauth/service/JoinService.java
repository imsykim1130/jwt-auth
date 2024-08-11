package syk.study.jwtauth.service;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import syk.study.jwtauth.dto.JoinDto;
import syk.study.jwtauth.entity.UserEntity;
import syk.study.jwtauth.repository.UserRepository;

@Service
@RequiredArgsConstructor
public class JoinService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder encoder;

    public void joinProcess(JoinDto joinDto) {
        // 유저 정보 추출
        String username = joinDto.getUsername();
        String password = joinDto.getPassword();

        // 가입 여부 확인
        boolean isExists = userRepository.existsByUsername(username);
        if (isExists) {
            return;
        }

        // 가입
        UserEntity userEntity = joinDto.toEntity(encoder.encode(password));
        userRepository.save(userEntity);
    }



}
