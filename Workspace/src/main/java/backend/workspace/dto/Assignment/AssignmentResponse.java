package backend.workspace.dto.Assignment;

import backend.workspace.entity.Assignment;

import java.time.OffsetDateTime;
import java.util.Map;

public record AssignmentResponse(

    Integer id,
    Integer workspaceId,
    String name,
    String description,
    OffsetDateTime dueData,
    Assignment.AssignmentStatus status,
    Map<String, Object> rubric,
    Map<String, Object> settings,
    boolean isExpired
) {
    public static AssignmentResponse fromEntity(Assignment assignment){
        return new AssignmentResponse(
                assignment.getId(),
                assignment.getWorkspace().getId(),
                assignment.getName(),
                assignment.getDescription(),
                assignment.getDueDate(),
                assignment.getStatus(),
                assignment.getRubric(),
                assignment.getSettings(),
                // ¿La fecha de entrega está ANTES del momento actual?,
                // si la fecha de entrega esta antes que la fecha de actual,
                // esta expirad, si es mayor esta activa
                assignment.getDueDate().isBefore(OffsetDateTime.now())
        );
    }
}
