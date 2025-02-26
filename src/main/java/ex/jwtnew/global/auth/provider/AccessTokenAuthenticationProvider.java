package ex.jwtnew.global.auth.provider;

import ex.jwtnew.global.auth.authentication.AccessTokenAuthentication;
import ex.jwtnew.global.auth.jwt.JwtStatus;
import ex.jwtnew.global.auth.jwt.JwtUtil;
import ex.jwtnew.global.redis.RedisUtil;
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

@Slf4j(topic = "AccessTokenAuthenticationProvider")
@Component
@RequiredArgsConstructor
public class AccessTokenAuthenticationProvider implements AuthenticationProvider {

    private final RedisUtil redisUtil;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String token = getTokenWithoutBearer(authentication);

        validateTokenStatus(token);

        String username = jwtUtil.getUsernameFromToken(token);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        // 로그아웃 여부 확인 후 예외처리

        validateLogout(username);

        return new AccessTokenAuthentication(userDetails, token, userDetails.getAuthorities());
    }

    private String getTokenWithoutBearer(Authentication authentication) {
        String tokenWithBearer = (String) authentication.getCredentials();
        return jwtUtil.getTokenWithoutBearer(tokenWithBearer);
    }

    private void validateTokenStatus(String token) {
        JwtStatus tokenStatus = jwtUtil.validateToken(token);

        if (tokenStatus.equals(JwtStatus.INVALID)) {
            // 무효한 토큰 에러 응답
            throw new HttpClientErrorException(HttpStatusCode.valueOf(400));
        }

        if (tokenStatus.equals(JwtStatus.EXPIRED)) {
            // 리프레쉬 하라는 에러 응답
            throw new HttpClientErrorException(HttpStatusCode.valueOf(401));
        }
    }

    private void validateLogout(String username) {
        redisUtil.get(username, String.class)
            .orElseThrow(() -> new HttpClientErrorException(HttpStatusCode.valueOf(401)));
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return AccessTokenAuthentication.class.isAssignableFrom(authentication);
    }
}