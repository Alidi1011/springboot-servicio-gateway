package com.aarteaga.gateway.server.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Collectors;
import java.util.Base64;
import java.util.Collection;

@Component
public class AuthenticationManagerJwt implements ReactiveAuthenticationManager{
	
	@Value("${config.security.oauth.jwt.key}")
    private String llaveJwt;

	@Override
	@SuppressWarnings("unchecked")
	public Mono<Authentication> authenticate(Authentication authentication) {
		
		return Mono.just(authentication.getCredentials().toString())
				.map(token -> {
					SecretKey llave = Keys.hmacShaKeyFor(Base64.getEncoder().encode(llaveJwt.getBytes()));
					return Jwts.parserBuilder().setSigningKey(llave).build().parseClaimsJws(token).getBody();		
				})
				.map(claims -> {
					String username = claims.get("use_name", String.class);
					List<String> roles = claims.get("authorities", List.class);
					Collection<GrantedAuthority> authorities = roles.stream().map(SimpleGrantedAuthority::new)
							.collect(Collectors.toList());
					return new UsernamePasswordAuthenticationToken(username, null, authorities);
				});
	}

}
