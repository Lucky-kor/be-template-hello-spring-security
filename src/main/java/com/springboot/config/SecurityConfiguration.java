package com.springboot.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfiguration {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // 씨큐리티6에선 람다식으로 바뀜
        http
                // frameOptions : 동일 도메인에서만 iframe접근이 가능
                // disalbe 할 수도 있지만 보안적인 이슈가 발생할 수 있음
                // h2의 뷰에는 frame을 써서sameOrigin은 허용해야함!
                .headers().frameOptions().sameOrigin()
                .and()
                // 로컬에선 활성화하면 404에러가 뜸
                .csrf().disable()
                .formLogin()
                .loginPage("/auths/login-form")
                .loginProcessingUrl("/process_login")
                .failureUrl("/auths/login-form?error")
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                .and()
                // 권한 없는 사용자의 접근시 나오는 페이지
                .exceptionHandling().accessDeniedPage("/auths/access-denied")
                .and()
                // 접근 권한 확인
                .authorizeHttpRequests(
                        authrize -> authrize
                                // **<<하위 모두
                                // *<<하위의 하위는 X(/가 추가시 불가능)
                                .antMatchers("/orders/**").hasRole("ADMIN")
                                .antMatchers("/members/my-page").hasRole("USER")
                                .antMatchers("/**").permitAll()
                );
//                // 어떤 요청이건
//                .anyRequest()
//                // 전부 허용
//                .permitAll();

        return http.build();
    }

    // 외부 것을 사용할 때는 메소드를 Bean으로 등록
    // 여기의 것들이 InMemoryMemberService에 들어간다
    // DB를 사용할 땐 필요하지X
//    @Bean
//    public UserDetailsManager userDetailsManager() {
//        UserDetails user =
//                // 패스워드 암호화
//                User.withDefaultPasswordEncoder()
//                    .username("hjd2110@naver.com")
//                    .password("1234")
//                    // 인가정보
//                    .roles("USER")
//                    .build();
//
//        UserDetails admin =
//                // 패스워드 암호화
//                User.withDefaultPasswordEncoder()
//                        .username("admin@naver.com")
//                        .password("1234")
//                        // 인가정보
//                        .roles("ADMIN")
//                        .build();
//
//        return new InMemoryUserDetailsManager(admin);
//    }

    // userDetailService에서 미리 생성한 InMemoryUser의 패스워드는
    // 내부적으로 PasswordEncoder를 통해 암호화된다
    // 디폴트는 bcrypt이다
    @Bean
    public PasswordEncoder passwordEncoder(){
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}
