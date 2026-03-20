package backend.workspace.dto.Workspace;

import backend.workspace.entity.Workspace;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import java.util.Map;

// Se usa en vez de lombok para que los datos sean inmutables
public record WorkspaceRequest(

    @NotBlank(message = "El nombre es obligatorio")
    @Size(min = 3, max = 100, message = "El nombre debe de tener entre 3 y 100 caracteres")
    String name,

    @NotBlank(message = "La descripción es obligatoria")
    @Size(max = 500, message = "La descripción no puede exceder 500 caracteres")
    String description,

    Workspace.WorkspaceStatus status,

    Map<String, Object> data
) {}
