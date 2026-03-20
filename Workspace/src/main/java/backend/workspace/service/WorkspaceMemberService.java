package backend.workspace.service;

import backend.workspace.dto.WorkspaceMember.WorkspaceMemberRequest;
import backend.workspace.dto.WorkspaceMember.WorkspaceMemberResponse;
import backend.workspace.entity.Workspace;
import backend.workspace.entity.WorkspaceMember;
import backend.workspace.exception.Workspace.WorkspaceNotFoundException;
import backend.workspace.exception.WorkspaceMember.MemberAlreadyExistException;
import backend.workspace.exception.WorkspaceMember.MemberNotFoundException;
import backend.workspace.repository.WorkspaceMemberRepository;
import backend.workspace.repository.WorkspaceRepository;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.UUID;

@Service
public class WorkspaceMemberService {

    private final WorkspaceMemberRepository workspaceMemberRepository;
    private final WorkspaceRepository workspaceRepository;

    public WorkspaceMemberService(WorkspaceMemberRepository workspaceMemberRepository, WorkspaceRepository workspaceRepository) {
        this.workspaceMemberRepository = workspaceMemberRepository;
        this.workspaceRepository = workspaceRepository;
    }

    //Agregar como ADMIN al creador de Workspace automaticamente
    public void addOwnerAsAdmin(Workspace workspace, UUID ownerId){
        WorkspaceMember owner = WorkspaceMember.builder()
                .userId(ownerId)
                .role(WorkspaceMember.Role.ADMIN)
                .build();

        // con el set guardamos el objeto de workspace en owner y luego hacemos el add al arrayList
        owner.setWorkspace(workspace);
        //Traemos los datos de la lista y luego agregamos el nuevo
        workspace.getMembers().add(owner);

        workspaceMemberRepository.save(owner);
    }

    // Invitar a un usuario a un workspace
    public WorkspaceMemberResponse addMember(WorkspaceMemberRequest request){

        Workspace workspace = findWorkspaceByCodeOrThrow(request.code());

        if (workspaceMemberRepository.existsByWorkspaceIdAndUserId(workspace.getId(), request.userId())){
            throw new MemberAlreadyExistException(request.userId(), workspace.getId());
        }

        WorkspaceMember member = WorkspaceMember.builder()
                .userId(request.userId())
                .role(WorkspaceMember.Role.MEMBER)
                .build();


        // con el set guardamos el objeto de workspace en workspaceMember y luego hacemos el add al arrayList
        member.setWorkspace(workspace);
        workspace.getMembers().add(member);

        WorkspaceMember saved = workspaceMemberRepository.save(member);
        return WorkspaceMemberResponse.fromEntity(saved, "Miembro agregado correctamente");
    }

    // Obtener todos los miembros del workspace
    public List<WorkspaceMemberResponse> getMembersByWorkspace(Integer workspaceId){
        // Comprueba en la tabla de workspace si existe el workspace
        findWorkspaceOrThrow(workspaceId);

        return workspaceMemberRepository.findByWorkspaceId(workspaceId)
                // Transforma la lista de WorkspaceMember a WorkspaceMemberResponse
                // Stream convierte la lista en un stream para que pueda ejecutar diferentes procesos
                .stream()
                // Recorre la lista de WorkspaceMember y por cada miembro lo convierte en un WorkspaceMemberResponse
                .map( member -> WorkspaceMemberResponse.fromEntity(member, "Miembro encontrado") )
                // toList convierte el stream en una lista
                .toList();
    }

    //Obtener todos los workspaces de un usuario
    public List<WorkspaceMemberResponse> getWorkspacesByUser(UUID userId) {
        return workspaceMemberRepository.findByUserId(userId)
                .stream()
                .map(member -> WorkspaceMemberResponse.fromEntity(member, "Workspace encontrado"))
                .toList();
    }

    /*
    //Actualizar el role de un miembro
    public WorkspaceMemberResponse updateMemberRole(Integer memberId, WorkspaceMember.Role newRole) {
        WorkspaceMember workspaceMember = findWorkspaceMemberById(memberId);
        workspaceMember.setRole(newRole);
        workspaceMemberRepository.save(workspaceMember);

        return WorkspaceMemberResponse.fromEntity(workspaceMember,  "Rol actualizado correctamente");
    }
    */

    //Eliminar un miembro del workspace
    public void deleteMember(Integer memberId){
        //Obtenemos los datos del miembro, con la comprobacion de que exista
        WorkspaceMember workspaceMember = findWorkspaceMemberById(memberId);

        //traemos el workspace del miembro
        Workspace workspace = workspaceMember.getWorkspace();
        //Lo eliminamos de la lista
        workspace.getMembers().remove(workspaceMember);
        //Lo eliminamos de la base de datos
        workspaceMemberRepository.delete(workspaceMember);
    }

    // Metodo privados

    private WorkspaceMember findWorkspaceMemberById(Integer id){
        return workspaceMemberRepository.findById(id)
                .orElseThrow(() -> new MemberNotFoundException(id));
    }

    private Workspace findWorkspaceOrThrow(Integer id) {
        return workspaceRepository.findById(id)
                .orElseThrow(() -> new WorkspaceNotFoundException(id));
    }

    private Workspace findWorkspaceByCodeOrThrow(String code) {
        return workspaceRepository.findByCode(code)
                .orElseThrow(() -> new WorkspaceNotFoundException("No existe un workspace con el codigo: " + code));
    }

}
