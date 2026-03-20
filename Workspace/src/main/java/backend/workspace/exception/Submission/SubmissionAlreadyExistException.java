package backend.workspace.exception.Submission;

import java.util.UUID;

public class SubmissionAlreadyExistException extends RuntimeException {

    public SubmissionAlreadyExistException(UUID userId, Integer assignmentId){
        super("El usuario" + userId + "ya entrego el assignment" + assignmentId);
    }

    public SubmissionAlreadyExistException(String message) {
        super(message);
    }
}
