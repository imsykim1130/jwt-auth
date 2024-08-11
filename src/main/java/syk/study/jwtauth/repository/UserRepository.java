package syk.study.jwtauth.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import syk.study.jwtauth.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    boolean existsByUsername(String username);
    UserEntity findByUsername(String username);
}
