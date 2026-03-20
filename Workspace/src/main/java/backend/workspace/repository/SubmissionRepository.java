package backend.workspace.repository;

import backend.workspace.entity.Assignment;
import backend.workspace.entity.Submission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface SubmissionRepository extends JpaRepository<Submission, Integer> {

    List<Submission> findByAssignmentId(Integer assignmentId);

    List<Submission> findByUserId(UUID userId);
    // verificamos si existe al menos un registro de submission donde haya un assignment y un usuario
    boolean existsByAssignmentIdAndUserId(Integer assignmentId, UUID userId);

    // Elimina todas las submissions de un assignment específico
    void deleteByAssignmentId(Integer assignmentId);

}
