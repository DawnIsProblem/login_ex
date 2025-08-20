package com.login.ex.domain.users.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.login.ex.common.exception.CustomException;
import com.login.ex.common.response.CommonResponse;
import com.login.ex.domain.users.dto.request.UsersSignUpRequestDto;
import com.login.ex.domain.users.dto.response.UsersSignUpResponseDto;
import com.login.ex.domain.users.entity.Users;
import com.login.ex.domain.users.error.UsersErrorCode;
import com.login.ex.domain.users.login.cookie.util.SignedCookieUtil;
import com.login.ex.domain.users.login.jwt.util.JwtUtil;
import com.login.ex.domain.users.login.session.dto.request.SessionSignInRequestDto;
import com.login.ex.domain.users.login.session.dto.response.SessionResponseDto;
import com.login.ex.domain.users.repository.UsersRepository;
import com.login.ex.domain.users.service.UsersService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Tag(name = "Login API", description = "로그인 관련 API")
public class UsersController {

    private final UsersService usersService;
    private final UsersRepository usersRepository;
    private final ObjectMapper om = new ObjectMapper();

    @Value("${COOKIE_SIGN_SECRET}")
    private String secret;

    @Value("${COOKIE_NAME:AUTH}")
    private String cookieName;

    @Value("${COOKIE_MAX_AGE:1800}")
    private int cookieMaxAge;

    private static final String SESSION_KEY = "LOGIN_USER";

    private final JwtUtil jwtUtil;

    @PostMapping("/signup")
    @Operation(summary = "계정 생성 API", description = "폼 로그인 예제에 공통적으로 사용할 계정을 생성합니다.")
    public CommonResponse<UsersSignUpResponseDto> signUp(
            @RequestBody @Valid UsersSignUpRequestDto request
    ){
        UsersSignUpResponseDto response = usersService.signUp(request);
        return CommonResponse.success("계정 생성 성공!", response);

    }

    @PostMapping("/session/login")
    @Operation(summary = "세션 로그인 API", description = "쿠키 기반의 세션 로그인을 시도합니다.")
    public CommonResponse<?> sessionLogin(
            @RequestBody @Valid SessionSignInRequestDto requestDto,
             HttpServletRequest request
    ){
        Users user = usersService.verifyCredential(requestDto.getLoginId(), requestDto.getPassword());
        request.getSession(true).setAttribute(SESSION_KEY,
                new SessionResponseDto(
                        user.getId(),
                        user.getLoginId(),
                        user.getRole().name(),
                        user.getNickname()
                )
        );
        return CommonResponse.success("세션 로그인 성공!");
    }

    @PostMapping("/session/logout")
    @Operation(summary = "세션 로그아웃 API", description = "쿠키 기반의 세션 로그아웃을 시도합니다.")
    public CommonResponse<?> sessionLogout(HttpServletRequest request, HttpServletResponse response) {
        var session = request.getSession(false);
        if (session != null) session.invalidate();
        return CommonResponse.success("세션 로그아웃 성공!");
    }

    @GetMapping("/session/me")
    @Operation(summary = "세션 로그인 상태 확인 API", description = "쿠키 기반의 세션 로그인이 잘 유지되고있는지 확인합니다.")
    public CommonResponse<SessionResponseDto> sessionMe(HttpServletRequest request) {
        var session = request.getSession(false);
        if (session == null) return CommonResponse.failure("세션이 없습니다. 로그인 해주세요");
        var principal = (SessionResponseDto) session.getAttribute(SESSION_KEY);
        if (principal == null) return CommonResponse.failure("세션이 없습니다. 로그인 해주세요");
        return CommonResponse.success("세션이 유지 중 입니다.", principal);
    }

    @PostMapping("/cookie/login")
    @Operation(summary = "쿠키 로그인 API", description = "쿠키만 사용하여 로그인을 시도합니다.")
    public Map<String, Object> login(
            @RequestBody SessionSignInRequestDto req, HttpServletResponse res
    ) throws Exception {
        Users user = usersService.verifyCredential(req.getLoginId(), req.getPassword());

        var util = new SignedCookieUtil(secret);
        long exp = Instant.now().getEpochSecond() + cookieMaxAge;

        Map<String, Object> payload = new HashMap<>();
        payload.put("sub", user.getLoginId());
        payload.put("role", user.getRole().name());
        payload.put("nickname", user.getNickname());
        payload.put("exp", exp);
        String json = om.writeValueAsString(payload);

        String token = util.sign(json);

        Cookie c = new Cookie(cookieName, token);
        c.setHttpOnly(true);
        c.setSecure(true);
        c.setPath("/");
        c.setMaxAge(cookieMaxAge);
        // SameSite=Lax는 코드로 직접 못 넣는 컨테이너도 있어요(스프링 부트 3.5는 기본 Lax). 프론트에서 POST시 Origin 검사 권장.
        res.addCookie(c);

        return Map.of("message","쿠키 로그인 성공!","exp",exp);
    }

    @PostMapping("/cookie/logout")
    @Operation(summary = "쿠키 로그아웃 API", description = "쿠키만 사용하여 로그아웃을 시도합니다.")
    public Map<String, Object> logout(HttpServletResponse res) {
        Cookie c = new Cookie(cookieName, "");
        c.setPath("/");
        c.setMaxAge(0);
        c.setHttpOnly(true);
        c.setSecure(true);
        res.addCookie(c);
        return Map.of("message","쿠키 로그아웃 성공!");
    }

    @GetMapping("/cookie/me")
    @Operation(summary = "쿠키 확인 API", description = "쿠키가 있는지 그리고 어떤 내용을 담고있는지 확인합니다.")
    public CommonResponse<Map<String, Object>> cookieMe(HttpServletRequest request, Principal principal) {
        // CookieAuthFilter가 SecurityContext에 인증을 넣었다면 principal이 존재합니다.
        if (principal == null) return CommonResponse.failure("인증 없음");
        return CommonResponse.success("쿠키 인증 OK", Map.of("name", principal.getName()));
    }


    @PostMapping("/jwt/login")
    @Operation(summary = "jwt 로그인 API", description = "jwt를 사용하여 로그인을 시도합니다.")
    public Map<String, Object> jwtLogin(@RequestBody @Valid SessionSignInRequestDto body) {
        String loginId = body.getLoginId();
        String password = body.getPassword();

        Users user = usersService.verifyCredential(loginId, password);

        String accessToken = jwtUtil.createAccessToken(
                user.getLoginId(),
                user.getRole().name(),
                user.getNickname()
        );
        String refreshToken = jwtUtil.createRefreshToken(user.getLoginId());

        long now = Instant.now().getEpochSecond();
        return Map.of(
                "message", "jwt login success",
                "accessToken", accessToken,
                "refreshToken", refreshToken,
                "issuedAt", now
        );
    }

    @PostMapping("/jwt/refresh")
    @Operation(summary = "jwt refresh-token갱신 API", description = "refresh-token을 갱산힙니다.")
    public Map<String, Object> refresh(
            @RequestBody Map<String, String> body
    ) {
        String refreshToken = body.get("refreshToken");
        var jws = jwtUtil.parse(refreshToken); // 만료/서명 검증 실패시 예외
        String loginId = jws.getBody().getSubject();

        // (선택) DB나 블랙리스트로 refresh 유효성 추가 검토

        Users user = usersRepository.findByLoginIdAndIsDeletedFalse(loginId)
                .orElseThrow(() -> new CustomException(UsersErrorCode.NOT_FOUND_USER));
        String role = user.getRole().name();
        String nickname = user.getNickname();
        String newAccess = jwtUtil.createAccessToken(loginId, role, nickname);

        return Map.of("accessToken", newAccess);
    }

    @GetMapping("/jwt/protected")
    @Operation(summary = "jwt 보호 확인 API", description = "jwt탈취당하지 않고 보호되고 있는지 확인합니다.")
    public Map<String, Object> protectedEndpoint() {
        // JwtAuthenticationFilter에서 SecurityContext에 인증이 들어온 상태
        return Map.of("message", "ok (jwt protected)");
    }

    @GetMapping("/common/me")
    @Operation(summary = "공통 상태 확인 API", description = "home.html에서 사용할 값을 불러들이는 공통 API입니다.")
    public CommonResponse<Map<String, Object>> me() {
        var auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated()) {
            return CommonResponse.failure("인증 없음");
        }

        String loginId = auth.getName(); // Jwt/쿠키/세션 필터에서 넣은 subject
        Users user = usersRepository.findByLoginIdAndIsDeletedFalse(loginId)
                .orElseThrow(() -> new CustomException(UsersErrorCode.NOT_FOUND_USER));

        String role = user.getRole().name();
        String nickname = user.getNickname();

        return CommonResponse.success("me",
                Map.of("loginId", loginId, "nickname", nickname, "role", role));
    }

    @PostMapping("/jwt/logout")
    @Operation(summary = "jwt 로그아웃 API", description = "클라이언트에 저장된 토큰 삭제를 안내합니다. 실제로 사용시 프론트 저장소에서 토큰을 지우면 될 뿐이므로 딱히 작업은 없습니다.")
    public Map<String, Object> jwtLogout() {
        // 서버에 유지 상태가 없으므로 실제로 할 일은 없음
        return Map.of("message", "client must delete tokens");
    }


}
