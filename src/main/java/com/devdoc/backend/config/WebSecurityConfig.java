package com.devdoc.backend.config;


import com.devdoc.backend.security.JwtAuthenticationFilter;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration // 이 클래스가 설정 클래스임을 나타냄
@EnableWebSecurity // Spring Security를 활성화
public class WebSecurityConfig {
	private static final Logger log = LoggerFactory.getLogger(WebSecurityConfig.class); // 로깅을 위한 로거 설정
	@Autowired // JwtAuthenticationFilter를 주입받음
	private JwtAuthenticationFilter jwtAuthenticationFilter;

	public WebSecurityConfig() {
	}

	@Bean // SecurityFilterChain 빈을 생성
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
				//.cors((cors) -> cors.configurationSource(this.corsConfigurationSource())) // CORS 설정 비활성화
				.csrf(csrf -> csrf.disable()) // CSRF 보호를 비활성화
				.httpBasic(httpBasic -> httpBasic.disable()) // HTTP Basic 인증을 비활성화
				.sessionManagement(sessionManagement -> sessionManagement.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 세션을 사용하지 않음
				.authorizeHttpRequests(authorize -> authorize
						.requestMatchers("/**").permitAll() // 특정 경로는 인증 없이 접근 허용
						.anyRequest().authenticated() // 나머지 모든 요청은 인증 필요
				)
				.headers(headers -> headers
						.frameOptions(frameOptions -> frameOptions.sameOrigin()) // 프레임 옵션 설정 (같은 출처에서만 프레임에 로드 가능)
				);

		http.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class); // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 전에 추가
		return http.build(); // SecurityFilterChain 빌드
	}

	@Bean // CorsConfigurationSource 빈을 생성
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration(); // CORS 설정 객체 생성
		configuration.setAllowedOriginPatterns(Arrays.asList("*")); // 허용할 오리진 패턴 설정
		configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS")); // 허용할 HTTP 메서드 설정
		configuration.setAllowedHeaders(Arrays.asList("*")); // 모든 헤더 허용
		configuration.setAllowCredentials(true); // 자격 증명 허용
		configuration.setMaxAge(3600L); // 캐시 최대 시간 설정
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource(); // URL 기반의 CORS 설정 소스 생성
		source.registerCorsConfiguration("/**", configuration); // 모든 경로에 대해 CORS 설정 적용
		return source; // CORS 설정 소스 반환
	}
}




