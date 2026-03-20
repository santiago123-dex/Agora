package backend.workspace.dto.Assignment;

import jakarta.validation.constraints.Future;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.time.OffsetDateTime;
import java.util.Map;

public record AssignmentRequest(

        @NotNull(message = "El Workspace Id es obligatorio")
        Integer workspaceId,

        @NotNull(message = "El Nombre es obligatorio")
        @Size(min = 3, max = 100, message = "El nombre tiene que tener entre 3 y 100 caracteres")
        String name,

        @Size(max = 500, message = "La descripcion no puede exceder de 500 caracteres")
        String description,

        @NotNull(message = "La fecha de entrega es obligatoria")
        @Future(message = "La fecha de entrega debe de ser futura")
        OffsetDateTime dueDate,

        Map<String, Object> rubric,

        Map<String, Object> settings
) {
}
