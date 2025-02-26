package ex.jwtnew.global.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import ex.jwtnew.global.auth.filter.AuthFilter;
import ex.jwtnew.global.auth.filter.LoginFilter;
import ex.jwtnew.global.auth.provider.JwtAuthenticationProvider;
import ex.jwtnew.global.auth.provider.UsernamePasswordAuthenticationProvider;
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

    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(jwtAuthenticationProvider, usernamePasswordAuthenticationProvider);
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
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        LoginFilter loginFilter,
        AuthFilter authFilter
    ) throws Exception {

        http.csrf(AbstractHttpConfigurer::disable);

        http.sessionManagement(manager -> manager.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        http.addFilterBefore(authFilter, LoginFilter.class);
        http.addFilterBefore(loginFilter, UsernamePasswordAuthenticationFilter.class);

        http.authorizeHttpRequests(authz -> authz
            .requestMatchers(PathRequest.toStaticResources().atCommonLocations()).permitAll()
            .requestMatchers(HttpMethod.POST, "/users/signup").permitAll()
            .anyRequest().authenticated()
        );

        return http.build();
    }
}
