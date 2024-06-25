// ResumeRepository.java

package com.devdoc.backend.repository;

import com.devdoc.backend.model.Resume;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface ResumeRepository extends JpaRepository<Resume, Integer> {
    List<Resume> findByUserId(String userId);
}