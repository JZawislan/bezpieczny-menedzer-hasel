package com.JZawislan.backend.auth.filter;

import java.io.IOException;
import java.util.List;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.JZawislan.backend.auth.model.AuthenticatedUser;
import com.JZawislan.backend.auth.service.JwtService;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

	private final JwtService jwtService;

	public JwtAuthenticationFilter(JwtService jwtService) {
		this.jwtService = jwtService;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String header = request.getHeader("Authorization");

		if (header != null && header.startsWith("Bearer ")
				&& SecurityContextHolder.getContext().getAuthentication() == null) {
			AuthenticatedUser user = jwtService.validateAndGetUser(header.substring(7));
			if (user != null) {
				UsernamePasswordAuthenticationToken authentication =
						new UsernamePasswordAuthenticationToken(
								user.username(),
								null,
								List.of(new SimpleGrantedAuthority("ROLE_" + user.role().name())));
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		}

		filterChain.doFilter(request, response);
	}
}

