package com.login.ex.domain.users.repository;

import com.login.ex.domain.users.entity.Users;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UsersRepository extends JpaRepository<Users, Long> {

    Optional<Users> findByLoginIdAndIsDeletedFalse(String loginId);

    boolean existsByLoginIdAndIsDeletedFalse(String loginId);
    boolean existsByEmailAndIsDeletedFalse(String email);
    boolean existsByNicknameAndIsDeletedFalse(String nickname);

}
