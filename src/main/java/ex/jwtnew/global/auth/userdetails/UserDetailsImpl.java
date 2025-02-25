package ex.jwtnew.global.auth.userdetails;

import ex.jwtnew.domain.user.UserRole;
import java.util.Collection;
import java.util.List;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

public record UserDetailsImpl(
    String username,
    String password,
    UserRole role
) implements UserDetails {

    @Override
    public String getPassword() {
        return this.password;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(role::getAuthority);
    }
}