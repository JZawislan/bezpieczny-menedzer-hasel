package com.JZawislan.backend.auth.dto;

import com.JZawislan.backend.auth.model.UserRole;

public record AuthResponse(String token, String username, UserRole role) {
}


