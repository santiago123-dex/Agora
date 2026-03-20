package backend.workspace.repository;

import backend.workspace.entity.WorkspaceMember;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

public interface WorkspaceMemberRepository extends JpaRepository<WorkspaceMember, Integer> {

    //Busca todos los miembros de un workspace
    List<WorkspaceMember> findByWorkspaceId(Integer workspaceId);

    //Busca todos los workspaces de un usuario
    List<WorkspaceMember> findByUserId(UUID userId);

    // Verifica si existe un miembro en un workspace
    boolean existsByWorkspaceIdAndUserId(Integer workspaceId, UUID userId);

    // Busca un miembro por workspaceId y userId, y trae la informacion del miembro
    Optional<WorkspaceMember>  findByWorkspaceIdAndUserId(Integer workspaceId, UUID userId);

    // Cuenta la cantidad de miembros de un workspace
    Long countByWorkspaceId(Integer workspaceId);

    // Elimina todos los miembros de un workspace
    void deleteMembersByWorkspaceId(Integer workspaceId);

}
