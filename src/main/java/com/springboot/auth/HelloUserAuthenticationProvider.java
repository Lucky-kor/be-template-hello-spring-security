package com.springboot.auth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Optional;

@Component
public class HelloUserAuthenticationProvider implements AuthenticationProvider {
    private final HelloUserDetailsServiceV2 userDetailsService;
    private final PasswordEncoder passwordEncoder;

    public HelloUserAuthenticationProvider(HelloUserDetailsServiceV2 userDetailsService, PasswordEncoder passwordEncoder) {
        this.userDetailsService = userDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        UsernamePasswordAuthenticationToken authToken =
                (UsernamePasswordAuthenticationToken) authentication;
        String username = authToken.getName();
        Optional.ofNullable(username).orElseThrow(() ->
                // 씨큐리티 예외
                new UsernameNotFoundException("Invalid User Name or User Password"));
        try{
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            String password = userDetails.getPassword();
            verifyCredentials(authToken.getCredentials(), password);

            // map은 못 들어옴!(순회X, set으로 바꾸거나 해야함)
            Collection<? extends GrantedAuthority> authorities = userDetails.getAuthorities();

            return UsernamePasswordAuthenticationToken.authenticated(username, password, authorities);
        }
        // 처리하지 않으면 톰캣 에러가 뜸
        catch (Exception e){
            throw  new UsernameNotFoundException(e.getMessage());
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return false;
    }

    private void verifyCredentials(Object credentials, String password){
        // 입력한 값과 불러온 기존 값이 같은지
        if(!passwordEncoder.matches((String) credentials, password))
            throw  new BadCredentialsException("Invalid User Name or User Password");


    }
}
