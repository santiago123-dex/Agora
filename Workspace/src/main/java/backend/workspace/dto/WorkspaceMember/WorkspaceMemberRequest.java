package backend.workspace.dto.WorkspaceMember;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import java.util.UUID;

// Se usa en vez de lombok para que los datos sean inmutables
public record WorkspaceMemberRequest(

        @NotBlank(message = "El codigo del workspace es obligatorio")
        String code,

        @NotNull(message = "El userId debe de ser obligatorio")
        UUID userId

) {}
