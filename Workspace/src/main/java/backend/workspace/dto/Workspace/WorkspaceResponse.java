package backend.workspace.dto.Workspace;

import backend.workspace.entity.Workspace;
import java.util.Map;


public record WorkspaceResponse(
     Integer id,
     String name,
     String description,
     Workspace.WorkspaceStatus status,
     String message,
     Map<String, Object> data
) {
    public static WorkspaceResponse fromEntity(Workspace workspace, String message){
        return new WorkspaceResponse(
        workspace.getId(),
        workspace.getName(),
        workspace.getDescription(),
        workspace.getStatus(),
        message,
        workspace.getData()
        );
    }

}
