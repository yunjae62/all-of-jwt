package ex.jwtnew.global.auth.authentication;

import java.util.Collection;
import lombok.Getter;
import lombok.ToString;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

@Getter
@ToString(callSuper = true)
public class JwtAuthenticationToken extends AbstractAuthenticationToken {

    private final String accessToken;
    private final String refreshToken;
    private final Object principal;

    /**
     * 인증 전 상태에서 사용할 생성자 (아직 인증이 완료되지 않은 상태이므로 권한 정보는 null)
     */
    public JwtAuthenticationToken(String accessToken, String refreshToken) {
        super(null);
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.principal = null;
        setAuthenticated(false);
    }

    /**
     * 인증 후 상태에서 사용할 생성자 (인증이 완료되어 사용자 정보와 권한 정보를 보유하는 상태)
     */
    public JwtAuthenticationToken(
        Object principal,
        String accessToken,
        String refreshToken,
        Collection<? extends GrantedAuthority> authorities
    ) {
        super(authorities);
        this.principal = principal;
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        setAuthenticated(true);
    }
    
    @Override
    public Object getCredentials() {
        return principal;
    }
}