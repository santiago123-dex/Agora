package backend.workspace.dto.Submission;

import backend.workspace.entity.Submission;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

public record SubmissionResponse(

        Integer Id,
        Integer AssignmentId,
        UUID userId,
        OffsetDateTime createdAt,
        Map<String, Object> content,
        Map<String, Object> files,
        Map<String, Object> aiResult
) {

    public static SubmissionResponse fromEntity(Submission submission){
        return new SubmissionResponse(
                submission.getId(),
                submission.getAssignment().getId(),
                submission.getUserId(),
                submission.getCreatedAt(),
                submission.getContent(),
                submission.getFiles(),
                submission.getAiResult()
        );
    }
}
