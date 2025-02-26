package ex.jwtnew.global.auth.provider;

import ex.jwtnew.global.auth.authentication.JwtAuthentication;
import ex.jwtnew.global.auth.jwt.JwtStatus;
import ex.jwtnew.global.auth.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.client.HttpClientErrorException;

@Slf4j(topic = "JwtAuthenticationProvider")
@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String tokenWithBearer = (String) authentication.getCredentials();
        String token = jwtUtil.getTokenWithoutBearer(tokenWithBearer);

        // 액세스 토큰 유효성 검사
        JwtStatus tokenStatus = jwtUtil.validateToken(token);
        validateTokenStatus(tokenStatus);

        String username = jwtUtil.getUsernameFromToken(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        // 로그아웃 여부 확인 후 예외처리

        return new JwtAuthentication(username, token, userDetails.getAuthorities());
    }

    private void validateTokenStatus(JwtStatus tokenStatus) {
        if (tokenStatus.equals(JwtStatus.INVALID)) {
            // 무효한 토큰 에러 응답
            throw new HttpClientErrorException(HttpStatusCode.valueOf(400));
        }

        if (tokenStatus.equals(JwtStatus.EXPIRED)) {
            // 리프레쉬 하라는 에러 응답
            throw new HttpClientErrorException(HttpStatusCode.valueOf(401));
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthentication.class.isAssignableFrom(authentication);
    }
}