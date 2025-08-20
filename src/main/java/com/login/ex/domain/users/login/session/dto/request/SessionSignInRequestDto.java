package com.login.ex.domain.users.login.session.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Getter;

@Getter
public class SessionSignInRequestDto {

    @Schema(description = "로그인 아이디", example = "user_1")
    private String loginId;

    @Schema(description = "비밀번호", example = "1234")
    private String password;

}
