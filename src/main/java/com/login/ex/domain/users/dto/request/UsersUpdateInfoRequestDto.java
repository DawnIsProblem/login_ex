package com.login.ex.domain.users.dto.request;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UsersUpdateInfoRequestDto {

    @Schema(description = "변경할 닉네임", example = "new_kkamang")
    private String nickname;

    @Schema(description = "변경할 이메일", example = "newkkamang@gmail.com")
    private String email;

}
