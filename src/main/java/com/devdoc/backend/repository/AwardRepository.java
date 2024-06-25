package com.devdoc.backend.repository;

import com.devdoc.backend.model.Award;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
public interface AwardRepository extends JpaRepository<Award, Integer> {

    List<Award> findByResumeId(Integer resumeId);
    Optional<Award> findByIdAndResumeId(Integer id, Integer resumeId);
}
