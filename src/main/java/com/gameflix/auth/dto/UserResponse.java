package com.gameflix.auth.dto;

import com.gameflix.auth.model.User;

import java.time.Instant;

public record UserResponse(Long id, String username, String email, Instant createdAt) {

    public static UserResponse from(User user) {
        return new UserResponse(user.getId(), user.getUsername(), user.getEmail(), user.getCreatedAt());
    }
}
