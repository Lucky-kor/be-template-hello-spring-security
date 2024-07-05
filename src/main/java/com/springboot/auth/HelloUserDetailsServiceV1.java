package com.springboot.auth;

import com.springboot.exception.BusinessLogicException;
import com.springboot.exception.ExceptionCode;
import com.springboot.member.Member;
import com.springboot.member.MemberRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

//UserDetailsService는 하나만 존재해야함!
//@Component
public class HelloUserDetailsServiceV1 implements UserDetailsService {
    private final MemberRepository memberRepository;
    private final HelloAuthorityUtils authorityUtils;

    public HelloUserDetailsServiceV1(MemberRepository memberRepository, HelloAuthorityUtils authorityUtils) {
        this.memberRepository = memberRepository;
        this.authorityUtils = authorityUtils;
    }

    @Override
    //필터체인 내부에서 인증이 끝나면 호출(인가)
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<Member> optionalMember = memberRepository.findByEmail(username);
        Member findmember = optionalMember.orElseThrow(() ->
                new BusinessLogicException(ExceptionCode.MEMBER_NOT_FOUND));
        // 관리자메일인지로 관리자 or 유저 권한부여
        Collection<? extends GrantedAuthority> authorities =
                authorityUtils.createAuthorities(findmember.getEmail());

        return new User(findmember.getEmail(), findmember.getPassword(), authorities);
    }
}
