package com.login.ex.domain.users.login.session.dto.response;

import lombok.AllArgsConstructor;
import lombok.Getter;

@AllArgsConstructor
@Getter
public class SessionResponseDto {

    private Long id;
    private String loginId;
    private String role;
    private String nickname;

}
