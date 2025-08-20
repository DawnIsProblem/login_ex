package com.login.ex.domain.users.login.cookie.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SignedCookieUtil {

    private final byte[] secret;

    public SignedCookieUtil(String secret) {
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    public String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] sig = mac.doFinal(payload.getBytes(StandardCharsets.UTF_8));
            return base64UrlEncode(payload.getBytes(StandardCharsets.UTF_8)) + "." + base64UrlEncode(sig);
        } catch (Exception e) {
            throw new IllegalStateException("Failed to sign payload", e);
        }
    }

    public String verifyAndExtract(String token) {
        String[] parts = token.split("\\.");
        if (parts.length != 2) throw new IllegalArgumentException("Invalid token format");

        String payloadB64 = parts[0];
        String sigB64 = parts[1];

        String payload = new String(base64UrlDecode(payloadB64), StandardCharsets.UTF_8);

        String expectedSigB64 = sign(payload).split("\\.")[1];

        if (!expectedSigB64.equals(sigB64)) {
            throw new IllegalArgumentException("Invalid token signature");
        }
        return payload;
    }

    private static String base64UrlEncode(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private static byte[] base64UrlDecode(String str) {
        return Base64.getUrlDecoder().decode(str);
    }

}