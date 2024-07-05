package com.springboot.member;

import com.springboot.exception.BusinessLogicException;
import com.springboot.exception.ExceptionCode;

import java.util.Optional;

public interface MemberService {
    Member createMember(Member member);
}
