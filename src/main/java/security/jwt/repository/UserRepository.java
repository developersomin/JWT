package security.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import security.jwt.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}