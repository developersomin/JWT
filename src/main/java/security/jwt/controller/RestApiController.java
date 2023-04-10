package security.jwt.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import security.jwt.domain.Role;
import security.jwt.domain.User;
import security.jwt.repository.UserRepository;

@RequiredArgsConstructor
@RestController
public class RestApiController {

    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final UserRepository userRepository;

    @GetMapping("home")
    public String home() {
        return "<h1>home<h1>";
    }

    @PostMapping("join")
    public String join(@RequestBody User user) {
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword()));
        user.setRole(Role.USER);
        userRepository.save(user);
        return "회원가입완료";
    }


    @GetMapping("/api/v1/user")
    public String user() {
        return "user";
    }


    @GetMapping("/api/v1/admin")
    public String admin() {
        return "admin";
    }


    @GetMapping("/api/v1/manage")
    public String manage() {
        return "manage";
    }
}
