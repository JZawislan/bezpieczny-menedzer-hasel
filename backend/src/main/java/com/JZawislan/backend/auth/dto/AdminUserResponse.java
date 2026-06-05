package com.JZawislan.backend.auth.dto;

import com.JZawislan.backend.auth.model.UserRole;

public record AdminUserResponse(Long id, String username, UserRole role, long vaultEntriesCount) {
}
