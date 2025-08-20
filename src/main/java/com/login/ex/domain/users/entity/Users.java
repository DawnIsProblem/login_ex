package com.login.ex.domain.users.entity;

import com.login.ex.domain.users.enums.Provider;
import com.login.ex.domain.users.enums.Role;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@NoArgsConstructor
@AllArgsConstructor
@Getter
@Setter
@Builder
@EntityListeners(AuditingEntityListener.class)
@Table(
        name = "users",
        indexes = {
                @Index(name = "uk_users_login_id", columnList = "login_id", unique = true),
                @Index(name = "uk_users_email", columnList = "email", unique = true),
                @Index(name = "uk_users_nickname", columnList = "nickname", unique = true),
                @Index(name = "uk_is_deleted", columnList = "is_deleted")
        }
)
public class Users {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "login_id", nullable = false, unique = true, length = 30)
    private String loginId;

    @Column(name = "password", length = 100)
    private String password;

    @Column(name = "email", nullable = false, unique = true, length = 100)
    private String email;

    @Column(name = "nickname", nullable = false, unique = true, length = 15)
    private String nickname;

    @Enumerated(EnumType.STRING)
    @Column(name = "provider", nullable = false)
    private Provider provider;

    @Column(name = "provider_id", length = 100)
    private String providerId;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private Role role;

    @Column(name = "is_deleted", nullable = false)
    private Boolean isDeleted;

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;

}
