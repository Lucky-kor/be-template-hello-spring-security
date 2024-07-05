package com.springboot.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class HelloAuthorityUtils {
    // application.yml에서 불러오기
    @Value("${mail.address.admin}")
    private String adminMailAdress;
    private final List<GrantedAuthority> ADMIN_ROLES =
            AuthorityUtils.createAuthorityList("ADMIN", "USER");
    private final List<GrantedAuthority> USER_ROLES =
            AuthorityUtils.createAuthorityList( "USER");
    private final List<String> ADMIN_ROLES_STRING = List.of("ADMIN", "USER");
    private final List<String> USER_ROLES_STRING = List.of("USER");

    public Collection<? extends GrantedAuthority> createAuthorities(String email) {
        if (email.equals(adminMailAdress))
            return ADMIN_ROLES;
        return USER_ROLES;
    }

    public List<GrantedAuthority> createAuthorities(List<String> roles) {
        return roles.stream()
                .map(role-> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toList());
    }

    //DB에 저장하기 위한 형태의 roles을 반환하는 메서드
    public List<String> createRoles(String email){
        if (email.equals(adminMailAdress))
            return ADMIN_ROLES_STRING;
        return USER_ROLES_STRING;
    }
}
