package com.gameflix.auth.dto;

public record LoginResponse(String token, String tokenType, long expiresIn) {
}
