package backend.workspace.exception.Assignment;

public class AssignmentExpiredException extends RuntimeException {

    public AssignmentExpiredException(Integer id){
        super("El assignment" + id + "ya expiro. No se puede entregar la tarea");
    }

    public AssignmentExpiredException(String message) {
        super(message);
    }
}
