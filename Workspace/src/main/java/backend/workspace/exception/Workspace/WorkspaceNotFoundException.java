package backend.workspace.exception.Workspace;

public class WorkspaceNotFoundException extends RuntimeException{

    public WorkspaceNotFoundException(Integer id) {
        super("Workspace no encontrado con id" + id);
    }

    public WorkspaceNotFoundException(String message){
        super(message);
    }

}
