package ex.jwtnew.global.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import ex.jwtnew.domain.user.dto.UserLoginReq;
import ex.jwtnew.global.auth.jwt.JwtUtil;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.client.HttpClientErrorException;

@Slf4j(topic = "login filter")
@RequiredArgsConstructor
public class LoginFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtUtil jwtUtil;
    private final ObjectMapper objectMapper;

    @PostConstruct
    public void setup() {
        setFilterProcessesUrl("/users/login");
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            // 요청 JSON 파싱
            UserLoginReq req = objectMapper.readValue(request.getInputStream(), UserLoginReq.class);
            log.info("[login try] loginId : {}, password : {}", req.username(), req.password());

            // 인증 처리 로직
            Authentication preAuthentication = new UsernamePasswordAuthenticationToken(req.username(), req.password(), null);
            Authentication postAuthentication = getAuthenticationManager().authenticate(preAuthentication);

            log.info("authentication : {}", postAuthentication);
            return postAuthentication;
        } catch (IOException e) {
            throw new HttpClientErrorException(HttpStatusCode.valueOf(500));
        }
    }

    /**
     * 로그인 성공 시 처리 로직
     */
    @Override
    protected void successfulAuthentication(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain chain,
        Authentication authResult
    ) throws IOException {

        log.info("success auth loginId : {}", authResult.getName());

        getResponseDtoWithTokensInHeader(authResult, response); // 헤더에서 토큰을 추가한 응답 DTO 생성

        response.setContentType(MediaType.APPLICATION_JSON_VALUE); // JSON 설정
        response.setCharacterEncoding(StandardCharsets.UTF_8.name()); // UTF8 설정하여 한글 표시

//        String result = objectMapper.writeValueAsString(res); // JSON to String 변환
        String result = "";
        response.getWriter().write(result);
    }

    private void getResponseDtoWithTokensInHeader(Authentication authentication, HttpServletResponse response) {
        // JWT 에 들어갈 loginId 를 userDetails 로부터 가져와서
        String username = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        String role = List.of(authentication.getAuthorities()).getFirst().toString();

        String accessToken = jwtUtil.createAccessToken(username, role);
        String refreshToken = jwtUtil.createRefreshToken(password, role);

        // response 객체의 헤더에 Bearer 접두사를 붙여 넣어준 뒤,
        response.addHeader(JwtUtil.ACCESS_TOKEN_HEADER, jwtUtil.setTokenWithBearer(accessToken));
        response.addHeader(JwtUtil.REFRESH_TOKEN_HEADER, jwtUtil.setTokenWithBearer(refreshToken));
    }

    private String getRoleInAuthentication(Authentication authResult) {
        List<? extends GrantedAuthority> list = new ArrayList<>(authResult.getAuthorities());
        return list.getFirst().getAuthority();
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