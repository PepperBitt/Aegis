package com.aegis.auth.infrastructure.seed;

import com.aegis.auth.domain.Role;
import com.aegis.auth.domain.User;
import com.aegis.auth.infrastructure.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class UserSeeder implements CommandLineRunner {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        seedUser("admin@aegis.local", "Aegis@123", "Admin User", Role.ADMIN);
        seedUser("analyst@aegis.local", "Aegis@123", "Analyst User", Role.ANALYST);
        seedUser("developer@aegis.local", "Aegis@123", "Developer User", Role.DEVELOPER);
        seedUser("auditor@aegis.local", "Aegis@123", "Auditor User", Role.AUDITOR);
    }

    private void seedUser(String email, String rawPassword, String fullName, Role role) {
        if (!userRepository.existsByEmail(email)) {
            User user = User.builder()
                    .email(email)
                    .passwordHash(passwordEncoder.encode(rawPassword))
                    .fullName(fullName)
                    .role(role)
                    .isActive(true)
                    .emailVerified(true)
                    .build();
            userRepository.save(user);
        }
    }
}
