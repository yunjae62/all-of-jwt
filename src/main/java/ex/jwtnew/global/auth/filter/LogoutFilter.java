package ex.jwtnew.global.auth.filter;

import ex.jwtnew.global.redis.RedisUtil;
import ex.jwtnew.global.security.WebSecurityConfig;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

@Slf4j
@RequiredArgsConstructor
public class LogoutFilter extends OncePerRequestFilter {

    private final RedisUtil redisUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        if (auth != null && auth.isAuthenticated()) {
            String username = auth.getName();
            redisUtil.delete(username);
        }

        response.setStatus(HttpServletResponse.SC_OK);
        response.getWriter().write("Logged out successfully");
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        // "/users/logout" URL이 아니라면 필터를 건너뜁니다.
        return !request.getServletPath().equals(WebSecurityConfig.LOGOUT_URL);
    }
}
