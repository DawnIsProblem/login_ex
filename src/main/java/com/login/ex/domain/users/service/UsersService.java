package com.login.ex.domain.users.service;

import com.login.ex.common.exception.CustomException;
import com.login.ex.domain.users.dto.request.UsersSignUpRequestDto;
import com.login.ex.domain.users.dto.response.UsersSignUpResponseDto;
import com.login.ex.domain.users.entity.Users;
import com.login.ex.domain.users.enums.Provider;
import com.login.ex.domain.users.enums.Role;
import com.login.ex.domain.users.error.UsersErrorCode;
import com.login.ex.domain.users.repository.UsersRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Transactional
public class UsersService {

    private final UsersRepository usersRepository;
    private final PasswordEncoder passwordEncoder;

    public UsersSignUpResponseDto signUp(UsersSignUpRequestDto request) {
        if(usersRepository.existsByLoginIdAndIsDeletedFalse(request.getLoginId())) {
            throw new CustomException(UsersErrorCode.EXIST_USER_ID);
        }
        if(usersRepository.existsByEmailAndIsDeletedFalse(request.getEmail())) {
            throw new CustomException(UsersErrorCode.EXIST_EMAIL);
        }
        if(usersRepository.existsByNicknameAndIsDeletedFalse(request.getNickname())) {
            throw new CustomException(UsersErrorCode.EXIST_NICKNAME);
        }

        Users user = Users.builder()
                .loginId(request.getLoginId())
                .password(passwordEncoder.encode(request.getPassword()))
                .email(request.getEmail())
                .nickname(request.getNickname())
                .provider(Provider.LOCAL)
                .role(Role.USER)
                .isDeleted(false)
                .build();

        Users saved = usersRepository.save(user);

        return UsersSignUpResponseDto.builder()
                .id(saved.getId())
                .loginId(saved.getLoginId())
                .email(saved.getEmail())
                .nickname(saved.getNickname())
                .build();
    }

    public Users verifyCredential(String loginId, String inputPassword) {
        Users user = usersRepository.findByLoginIdAndIsDeletedFalse(loginId)
                .orElseThrow(() -> new CustomException(UsersErrorCode.NOT_FOUND_USER));

        if ( user.getProvider() != Provider.LOCAL) {
            throw new CustomException(UsersErrorCode.WRONG_PROVIDER);
        }

        if (!passwordEncoder.matches(inputPassword, user.getPassword())) {
            throw new CustomException(UsersErrorCode.WRONG_PASSWORD);
        }

        return user;
    }
}
