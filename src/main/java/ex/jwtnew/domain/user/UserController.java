package ex.jwtnew.domain.user;

import ex.jwtnew.domain.user.dto.UserLoginReq;
import ex.jwtnew.domain.user.dto.UserSignupReq;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.HttpClientErrorException;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/users")
public class UserController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/signup")
    public ResponseEntity<User> signup(@RequestBody UserSignupReq request) {
        if (userRepository.existsByUsername(request.username())) {
            throw new HttpClientErrorException(HttpStatusCode.valueOf(400));
        }

        String encodedPassword = passwordEncoder.encode(request.password());
        User user = new User(request.username(), encodedPassword);
        User savedUser = userRepository.save(user);

        return ResponseEntity.ok(savedUser);
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody UserLoginReq request) {
        User user = userRepository.findByUsername(request.username())
            .orElseThrow(() -> new HttpClientErrorException(HttpStatusCode.valueOf(404)));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new HttpClientErrorException(HttpStatusCode.valueOf(404));
        }

        return ResponseEntity.ok(user);
    }
}
