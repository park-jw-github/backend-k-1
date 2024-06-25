package com.devdoc.backend.model;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.GenericGenerator;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import java.util.List;

// UserEntity: 사용자 정보를 데이터베이스에 저장하고 관리하기 위한 Entity

@Data
@Entity
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table(uniqueConstraints = {@UniqueConstraint(columnNames = "email")})
public class UserEntity {
	@Id
	@GeneratedValue(generator = "system-uuid")
	@GenericGenerator(name = "system-uuid", strategy = "uuid")
	private String id; // 사용자 고유 ID

	@Column(nullable = false)
	private String username; // 사용자 닉네임

	@Column(nullable = false)
	private String email; // 사용자 이메일

	@Column(nullable = false)
	private String password; // 사용자 비밀번호

	private LocalDateTime createdAt;

	@OneToMany(mappedBy = "user", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	private List<Resume> resumes; // 사용자와 연결된 이력서 목록

	@PrePersist
	protected void onCreate() {
		this.createdAt = LocalDateTime.now(); // 엔티티가 생성될 때 자동으로 현재 시간이 설정됨
	}
}


