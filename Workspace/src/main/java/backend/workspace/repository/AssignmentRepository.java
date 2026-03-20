package backend.workspace.repository;

import backend.workspace.entity.Assignment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AssignmentRepository extends JpaRepository<Assignment, Integer> {

    List<Assignment> findByWorkspaceId(Integer workspaceId);

    // Busca todas las tareas de un workspace dependiendo que status le digamos
    List<Assignment> findByWorkspaceIdAndStatus(Integer workspaceId, Assignment.AssignmentStatus status);

    // Busca todas las tareas que esten publicadas y que su fecha de vencimiento sea anterior a la fecha actual
    List<Assignment> findByDueDateBeforeAndStatus (OffsetDateTime date, Assignment.AssignmentStatus status);



}
