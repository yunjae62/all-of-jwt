package ex.jwtnew.global.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import ex.jwtnew.global.auth.filter.AuthFilter;
import ex.jwtnew.global.auth.filter.ExceptionFilter;
import ex.jwtnew.global.auth.filter.LoginFilter;
import ex.jwtnew.global.auth.filter.LogoutFilter;
import ex.jwtnew.global.auth.filter.RefreshFilter;
import ex.jwtnew.global.auth.handler.RefreshSuccessHandler;
import ex.jwtnew.global.auth.provider.AccessTokenAuthenticationProvider;
import ex.jwtnew.global.auth.provider.RefreshTokenAuthenticationProvider;
import ex.jwtnew.global.auth.provider.UsernamePasswordAuthenticationProvider;
import ex.jwtnew.global.redis.RedisUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class WebSecurityConfig {

    public static final String SIGNUP_URL = "/users/signup";
    public static final String LOGIN_URL = "/users/login";
    public static final String LOGOUT_URL = "/users/logout";
    public static final String REFRESH_URL = "/users/refresh";

    private final RefreshTokenAuthenticationProvider refreshTokenAuthProvider;
    private final AccessTokenAuthenticationProvider accessTokenAuthProvider;
    private final UsernamePasswordAuthenticationProvider usernamePasswordAuthProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(refreshTokenAuthProvider, accessTokenAuthProvider, usernamePasswordAuthProvider);
    }

    @Bean
    public RefreshFilter refreshFilter(RefreshSuccessHandler refreshSuccessHandler) {
        return new RefreshFilter(refreshSuccessHandler, authenticationManager());
    }

    @Bean
    public AuthFilter authFilter() {
        return new AuthFilter(authenticationManager());
    }

    @Bean
    public LoginFilter loginFilter(ObjectMapper objectMapper, AuthenticationSuccessHandler loginSuccessHandler) {
        LoginFilter filter = new LoginFilter(objectMapper, loginSuccessHandler);
        filter.setAuthenticationManager(authenticationManager());
        return filter;
    }

    @Bean
    public LogoutFilter logoutFilter(RedisUtil redisUtil) {
        return new LogoutFilter(redisUtil);
    }

    @Bean
    public ExceptionFilter exceptionFilter(ObjectMapper objectMapper) {
        return new ExceptionFilter(objectMapper);
    }

    @Bean
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        LoginFilter loginFilter,
        LogoutFilter logoutFilter,
        AuthFilter authFilter,
        RefreshFilter refreshFilter,
        ExceptionFilter exceptionFilter
    ) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class);
        http.addFilterBefore(logoutFilter, LoginFilter.class);
        http.addFilterBefore(authFilter, LogoutFilter.class);
        http.addFilterBefore(refreshFilter, AuthFilter.class);
        http.addFilterBefore(exceptionFilter, RefreshFilter.class);

        http.authorizeHttpRequests(authz -> authz
            .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
            .requestMatchers(HttpMethod.POST, SIGNUP_URL).permitAll()
            .requestMatchers(HttpMethod.POST, REFRESH_URL).permitAll()
            .anyRequest().authenticated()
        );

        return http.build();
    }
}
