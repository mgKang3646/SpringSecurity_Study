package io.security.basicsecurity;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Configuration
@EnableWebSecurity //Security에 필요한 여러 클래스를 함께 실행시켜주는 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //인가정책
        http
                .authorizeRequests()
                .anyRequest().authenticated(); //어떤 요청에도 인증을 받도록 설정

        //인증정책
        http
                .formLogin()
        ;
    }
}
