package com.login.ex.common.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI() {
        return new OpenAPI()
//                .components(new Components()
//                        .addSecuritySchemes("Authorization",
//                                new SecurityScheme()
//                                        .type(SecurityScheme.Type.APIKEY)
//                                        .in(SecurityScheme.In.HEADER)
//                                        .bearerFormat("JWT")
//                                        .name("Authorization")
//                        )
//                )
//                .addSecurityItem(new SecurityRequirement().addList("Authorization"))
                .info(new Info()
                        .title("Login Project / 여러 로그인 구현 예제 수행 API 명세서")
                        .version("1.0.0")
                        .description(
                                """
                                세션 기반, JWT 기반, 쿠키 기반 폼 로그인을 구현합니다.
                                \n\n
                                소셜 로그인을 구현합니다. 소셜 로그인은 필요에 따라 JWT를 추가해서 관리합니다.
                                \n\n
                                thymeleaf를 활용하여 페이지를 작성합니다.
                                """
                        )
                );
    }

}