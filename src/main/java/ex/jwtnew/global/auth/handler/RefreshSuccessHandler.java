package ex.jwtnew.global.auth.handler;

import ex.jwtnew.global.auth.jwt.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class RefreshSuccessHandler {

    private final JwtUtil jwtUtil;

    public void onAuthenticationSuccess(HttpServletResponse response, Authentication authentication) throws IOException {
        getResponseDtoWithTokensInHeader(authentication, response); // 헤더에서 토큰을 추가한 응답 DTO 생성

        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // JSON 설정
        response.setCharacterEncoding(StandardCharsets.UTF_8.name()); // UTF8 설정하여 한글 표시

//        String result = objectMapper.writeValueAsString(res); // JSON to String 변환
        String result = "";
        response.getWriter().write(result);
    }

    private void getResponseDtoWithTokensInHeader(Authentication authentication, HttpServletResponse response) {
        UserDetails principal = (UserDetails) authentication.getPrincipal();
        String username = principal.getUsername();
        String role = List.of(principal.getAuthorities()).getFirst().toString();

        String accessToken = jwtUtil.createAccessToken(username, role);
        String refreshToken = jwtUtil.createRefreshToken(username, role);

        response.addHeader(JwtUtil.ACCESS_TOKEN_HEADER, jwtUtil.setTokenWithBearer(accessToken));
        response.addHeader(JwtUtil.REFRESH_TOKEN_HEADER, jwtUtil.setTokenWithBearer(refreshToken));
    }
}
