package ex.jwtnew.global.auth.provider;

import ex.jwtnew.global.auth.authentication.JwtAuthenticationToken;
import ex.jwtnew.global.auth.jwt.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Slf4j(topic = "AccessTokenAuthenticationProvider")
@Component
@RequiredArgsConstructor
public class JwtAuthenticationProvider implements AuthenticationProvider {

    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        JwtAuthenticationToken jwtAuthToken = (JwtAuthenticationToken) authentication;
        String accessToken = jwtAuthToken.getAccessToken();
        String username = jwtUtil.getUsernameFromToken(accessToken);
        UserDetails userDetails = userDetailsService.loadUserByUsername(username);

        if (userDetails == null) {
            throw new RuntimeException("사용자 정보를 찾을 수 없습니다: " + username);
        }

        JwtAuthenticationToken authResult = new JwtAuthenticationToken(
            userDetails,
            accessToken,
            jwtAuthToken.getRefreshToken(),
            userDetails.getAuthorities()
        );

        log.info("Authenticated user: {}", username);
        return authResult;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return JwtAuthenticationToken.class.isAssignableFrom(authentication);
    }
}