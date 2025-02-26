package ex.jwtnew.global.auth.filter;

import ex.jwtnew.global.auth.authentication.JwtAuthentication;
import ex.jwtnew.global.auth.jwt.JwtStatus;
import ex.jwtnew.global.auth.jwt.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j(topic = "AuthFilter")
@RequiredArgsConstructor
public class AuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {

        // 헤더에서 액세스 토큰 추출 (Bearer 접두어 제거)
        String header = request.getHeader(JwtUtil.ACCESS_TOKEN_HEADER);
        String accessToken = jwtUtil.getTokenWithoutBearer(header);
        log.info("accessToken : {}", accessToken);

        // 토큰이 없으면 인증 처리 없이 다음 필터로 전달
        if (!StringUtils.hasText(accessToken)) {
            filterChain.doFilter(request, response);
            return;
        }

        // 액세스 토큰 유효성 검사
        JwtStatus accessTokenStatus = jwtUtil.validateToken(accessToken);

        if (accessTokenStatus != JwtStatus.VALID) {
            log.warn("Invalid access token: {}", accessTokenStatus);
            filterChain.doFilter(request, response);
            return;
        }

        // JwtAuthenticationToken을 생성
        Authentication jwtAuthToken = new JwtAuthentication(accessToken);

        // AuthenticationManager를 통해 인증 처리
        Authentication authResult = authenticationManager.authenticate(jwtAuthToken);

        // 인증 결과를 SecurityContext에 설정
        SecurityContextHolder.getContext().setAuthentication(authResult);

        filterChain.doFilter(request, response);
    }
}