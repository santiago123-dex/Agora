package backend.workspace.exception.WorkspaceMember;

import java.util.UUID;

public class MemberAlreadyExistException extends RuntimeException{

    public MemberAlreadyExistException(UUID userId, Integer WorkspaceId){
        super("El usuario " + userId + " ya pertenece al workspace " + WorkspaceId);
    }

    public MemberAlreadyExistException(String message){
        super(message);
    }

}
