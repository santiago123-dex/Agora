package backend.workspace.dto.Submission;

import jakarta.validation.constraints.NotNull;

import java.util.Map;
import java.util.UUID;

public record SubmissionRequest(

        @NotNull(message = "El assignment ID es obligatorio")
        Integer assignmentId,

        @NotNull(message = "El user ID es obligatorio")
        UUID userId,

        Map<String, Object> content,
        Map<String, Object> files

) {
}
