package com.login.ex.domain.users.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UsersSignUpRequestDto {

    @Schema(description = "로그인 아이디", example = "user_1")
    private String loginId;

    @Schema(description = "비밀번호(BCrypt로 암호화됩니다.)", example = "1234")
    private String password;

    @Schema(description = "이메일", example = "kkamang@gmail.com")
    private String email;

    @Schema(description = "닉네임", example = "까망")
    private String nickname;

}
