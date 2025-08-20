package com.login.ex.domain.users.error;

import com.login.ex.common.error.ErrorCode;
import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
@AllArgsConstructor
public enum UsersErrorCode implements ErrorCode {

    EXIST_USER_ID(HttpStatus.BAD_REQUEST, "U001", "이미 존재하는 사용자 아이디입니다."),
    EXIST_EMAIL(HttpStatus.BAD_REQUEST, "U002", "이미 존재하는 이메일입니다."),
    EXIST_NICKNAME(HttpStatus.BAD_REQUEST, "U003", "이미 존재하는 닉네임입니다."),
    NOT_FOUND_USER(HttpStatus.NOT_FOUND, "U004", "사용자를 찾을 수 없습니다."),
    WRONG_PASSWORD(HttpStatus.BAD_REQUEST, "U005", "비밀번호가 옳지 않습니다."),
    WRONG_PROVIDER(HttpStatus.BAD_REQUEST, "U006", "폼 로그인 아이디가 아닙니다.");

    private final HttpStatus status;
    private final String code;
    private final String message;

}
