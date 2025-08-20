package com.login.ex.common.exception;

import com.login.ex.common.response.CommonResponse;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    // 따로 더 구체적인 선언이 없다면, CustomException을 상속받은 모든 예외가 이곳으로 옴.
    // 따라서 이 양식을 따르는 한 따로 더 만들 익셉션 핸들러 메서드가 없음.
    @ExceptionHandler(CustomException.class)
    public ResponseEntity<CommonResponse<Void>> handleCustom(CustomException e) {
        var ec = e.getErrorCode();
        return ResponseEntity
                .status(ec.getStatus())
                .body(CommonResponse.failure(ec.getCode() + ": " + ec.getMessage()));
    }

}