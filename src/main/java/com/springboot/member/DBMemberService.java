package com.springboot.member;

import com.springboot.auth.HelloAuthorityUtils;
import com.springboot.exception.BusinessLogicException;
import com.springboot.exception.ExceptionCode;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

@Transactional
public class DBMemberService implements MemberService {

   private final MemberRepository memberRepository;
   private final PasswordEncoder passwordEncoder;
   private final HelloAuthorityUtils authorityUtils;

    public DBMemberService(MemberRepository memberRepository, PasswordEncoder passwordEncoder, HelloAuthorityUtils authorityUtils) {
        this.memberRepository = memberRepository;
        this.passwordEncoder = passwordEncoder;
        this.authorityUtils = authorityUtils;
    }

    @Override
    public Member createMember(Member member) {
        verifyExistsEmail(member.getEmail());

        // 패스워드는 단방향 암호화로 저장하고 그것끼리 비교
        String encrytedPassword = passwordEncoder.encode(member.getPassword());
        member.setPassword(encrytedPassword);
        List<String> roles = authorityUtils.createRoles(member.getEmail());
        member.setRoles(roles);
        Member savedMember = memberRepository.save(member);

        System.out.println("# Create Member in DB");

        return savedMember;
    }

    private void verifyExistsEmail(String email) {
        Optional<Member> member = memberRepository.findByEmail(email);
        if (member.isPresent())
            throw new BusinessLogicException(ExceptionCode.MEMBER_EXISTS);
    }
}
