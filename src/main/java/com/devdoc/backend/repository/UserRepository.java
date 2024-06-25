package com.devdoc.backend.repository;


import com.devdoc.backend.model.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

// UserRepository: 사용자 정보를 데이터베이스에서 조회하고 관리

@Repository
public interface UserRepository extends JpaRepository<UserEntity, String> {

	UserEntity findByEmail(String email); // 이메일을 통해 사용자 정보 조회
	Boolean existsByEmail(String email); // 이메일 중복 여부 확인
	UserEntity findByEmailAndPassword(String email, String password); // 이메일과 비밀번호를 통해 사용자 정보 조회

}

