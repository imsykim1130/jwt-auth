package syk.study.jwtauth.dto;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import syk.study.jwtauth.entity.UserEntity;

@Getter
@Setter
@RequiredArgsConstructor
public class JoinDto {
    private String username;
    private String password;

    public UserEntity toEntity() {
        return UserEntity.builder()
                .username(username)
                .password(password)
                .role("ROLE_USER")
                .build();
    }

    public UserEntity toEntity(String encodedPassword) {
        return UserEntity.builder()
                .username(username)
                .password(encodedPassword)
                .role("USER_ROLE")
                .build();
    }

}
