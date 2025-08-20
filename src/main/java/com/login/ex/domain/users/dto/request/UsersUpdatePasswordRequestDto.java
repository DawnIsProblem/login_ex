package com.login.ex.domain.users.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UsersUpdatePasswordRequestDto {

    @Schema(description = "현재 비밀번호", example = "1234")
    private String oldPassword;

    @Schema(description = "변경할 비밀번호", example = "4321")
    private String newPassword;

}
