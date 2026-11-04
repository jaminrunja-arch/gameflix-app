package com.gameflix.auth.service;

import com.gameflix.auth.dto.LoginRequest;
import com.gameflix.auth.dto.LoginResponse;
import com.gameflix.auth.dto.RegisterRequest;
import com.gameflix.auth.dto.UserResponse;
import com.gameflix.auth.exception.DuplicateUserException;
import com.gameflix.auth.exception.InvalidCredentialsException;
import com.gameflix.auth.exception.InvalidInputException;
import com.gameflix.auth.model.User;
import com.gameflix.auth.repository.UserRepository;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Optional;

@Service
public class AuthService {

    private static final int BCRYPT_MAX_BYTES = 72;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;
    private final String dummyHash;

    public AuthService(UserRepository userRepository, PasswordEncoder passwordEncoder, TokenService tokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenService = tokenService;
        this.dummyHash = passwordEncoder.encode("not-a-real-password");
    }

    // not @Transactional on purpose, the constraint error has to be caught here and turned into a 409
    public UserResponse register(RegisterRequest request) {
        if (request.password().getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_BYTES) {
            throw new InvalidInputException("Password is too long");
        }

        User user = new User();
        user.setUsername(request.username().trim());
        user.setEmail(normalizeEmail(request.email()));
        user.setPassword(passwordEncoder.encode(request.password()));

        try {
            User saved = userRepository.saveAndFlush(user);
            return UserResponse.from(saved);
        } catch (DataIntegrityViolationException ex) {
            String cause = String.valueOf(ex.getMostSpecificCause().getMessage());
            if (cause.contains("uk_users_email")) {
                throw new DuplicateUserException("Email is already registered");
            }
            if (cause.contains("uk_users_username")) {
                throw new DuplicateUserException("Username is already taken");
            }
            throw ex;
        }
    }

    public LoginResponse login(LoginRequest request) {
        if (request.email() == null || request.password() == null
                || request.password().getBytes(StandardCharsets.UTF_8).length > BCRYPT_MAX_BYTES) {
            throw new InvalidCredentialsException();
        }

        Optional<User> user = userRepository.findByEmail(normalizeEmail(request.email()));
        if (user.isEmpty()) {
            // still run a bcrypt check so a missing email takes about as long as a wrong password
            passwordEncoder.matches(request.password(), dummyHash);
            throw new InvalidCredentialsException();
        }
        if (!passwordEncoder.matches(request.password(), user.get().getPassword())) {
            throw new InvalidCredentialsException();
        }
        return tokenService.createToken(user.get());
    }

    public UserResponse getCurrentUser(String subject) {
        Long id;
        try {
            id = Long.valueOf(subject);
        } catch (NumberFormatException ex) {
            throw new InvalidCredentialsException();
        }
        return userRepository.findById(id)
                .map(UserResponse::from)
                .orElseThrow(InvalidCredentialsException::new);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase(Locale.ROOT);
    }
}
