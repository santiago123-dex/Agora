package backend.workspace.exception.WorkspaceMember;

public class MemberNotFoundException extends RuntimeException{

    public MemberNotFoundException(Integer id){
        super("Miembro no encontrado con id" + id);
    }

    public MemberNotFoundException(String message){
        super(message);
    }

}
