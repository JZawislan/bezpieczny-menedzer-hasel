package com.JZawislan.backend.auth;

public record AuthResponse(String token, String username, UserRole role) {
}
