package backend.workspace.exception.Assignment;

public class AssignmentNotFoundException extends RuntimeException{

    public AssignmentNotFoundException(Integer id){
        super("Assignment no encontrado con id:" + id);
    }

    public AssignmentNotFoundException(String message){
        super(message);
    }

}
