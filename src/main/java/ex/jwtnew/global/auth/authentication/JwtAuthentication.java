package ex.jwtnew.global.auth.authentication;

import java.util.Collection;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@Getter
@ToString(callSuper = true)
public class JwtAuthentication extends AbstractAuthenticationToken {

    private final String username; // username
    private final String token; // jwt token

    /**
     * 인증 전
     */
    public JwtAuthentication(String token) {
        super(null);
        this.token = token;
        this.username = null;
        setAuthenticated(false);
    }

    /**
     * 인증 후
     */
    public JwtAuthentication(
        String username,
        String token,
        Collection<? extends GrantedAuthority> authorities
    ) {
        super(authorities);
        this.username = username;
        this.token = token;
        setAuthenticated(true);
    }

    @Override
    public Object getPrincipal() {
        return this.username;
    }

    @Override
    public Object getCredentials() {
        return this.token;
    }
}