package backend.workspace.dto.WorkspaceMember;

import backend.workspace.entity.WorkspaceMember;

import java.util.UUID;

public record WorkspaceMemberResponse(
    Integer id,
    Integer workspaceId,
    UUID userId,
    WorkspaceMember.Role role,
    String message
) {

    public static WorkspaceMemberResponse fromEntity(WorkspaceMember member, String message){
        return new WorkspaceMemberResponse(
                member.getId(),
                member.getWorkspace().getId(),
                member.getUserId(),
                member.getRole(),
                message
        );
    }
}
