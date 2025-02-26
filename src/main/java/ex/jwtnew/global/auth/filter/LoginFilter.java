package ex.jwtnew.global.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import ex.jwtnew.domain.user.dto.UserLoginReq;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.HttpClientErrorException;

@Slf4j(topic = "LoginFilter")
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final ObjectMapper objectMapper;
    private final AuthenticationSuccessHandler loginSuccessHandler;

    @PostConstruct
    public void setup() {
        this.setAuthenticationSuccessHandler(loginSuccessHandler);
        setFilterProcessesUrl("/users/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            // 요청 JSON 파싱
            UserLoginReq req = objectMapper.readValue(request.getInputStream(), UserLoginReq.class);

            // 인증 처리 로직
            Authentication preAuthentication = new UsernamePasswordAuthenticationToken(req.username(), req.password(), null);
            return getAuthenticationManager().authenticate(preAuthentication);
        } catch (IOException e) {
            throw new HttpClientErrorException(HttpStatusCode.valueOf(500));
        }
    }

    /**
     * 로그인 실패 시 처리 로직
     */
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) {
        log.info("login failed message : {}", failed.getMessage());
        throw new HttpClientErrorException(HttpStatusCode.valueOf(404));
    }
}