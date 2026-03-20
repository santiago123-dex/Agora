package backend.workspace.exception.Submission;

public class SubmissionNotFoundException extends RuntimeException {

    public SubmissionNotFoundException(Integer id){
        super("Submission no encontrado con id" + id);
    }

    public SubmissionNotFoundException(String message) {
        super(message);
    }
}
