package com.login.ex.domain.users.dto.response;

import lombok.Builder;
import lombok.Getter;

@Getter
@Builder
public class UsersSignUpResponseDto {

    private Long id;
    private String loginId;
    private String nickname;
    private String email;

}
