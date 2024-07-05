package com.springboot.member;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

public class InMemoryMemberService implements MemberService {
    // DI로 의존성 주입
    private final UserDetailsManager userDetailsManager;
    private final PasswordEncoder passwordEncoder;

    public InMemoryMemberService(UserDetailsManager userDetailsManager, PasswordEncoder passwordEncoder) {
        this.userDetailsManager = userDetailsManager;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Member createMember(Member member) {
        // 씨큐리티 컨텍스트에 보관됨
        List<GrantedAuthority> authorities =
                createAuthorities(Member.MemberRole.ROLE_USER.name());
        String encryptedPassword = passwordEncoder.encode(member.getPassword());
        //UserDetailsDB 등의 저장소에 저장된 사용자의 Username과 사용자의 자격을 증명해주는
        // 크리덴셜(Credential)인 Password 그리고 사용자의 권한 정보를 포함하는 컴포넌트
        UserDetails userDetails = new User(member.getEmail(), encryptedPassword, authorities);
        userDetailsManager.createUser(userDetails);
        return member;
    }

    private List<GrantedAuthority> createAuthorities(String... roles) {
        return Arrays.stream(roles)
                .map(role -> new SimpleGrantedAuthority(role))
                .collect(Collectors.toList());
    }
}
