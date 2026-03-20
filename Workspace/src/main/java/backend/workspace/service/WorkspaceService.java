package backend.workspace.service;

import backend.workspace.dto.Workspace.WorkspaceRequest;
import backend.workspace.dto.Workspace.WorkspaceResponse;
import backend.workspace.entity.Workspace;
import backend.workspace.exception.Workspace.WorkspaceNotFoundException;

import backend.workspace.repository.WorkspaceRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;



@Service
public class WorkspaceService {

    private final WorkspaceRepository workspaceRepository;
    private final WorkspaceMemberService workspaceMemberService;

    public WorkspaceService(WorkspaceRepository workspaceRepository, WorkspaceMemberService workspaceMemberService) {
        this.workspaceRepository = workspaceRepository;
        this.workspaceMemberService = workspaceMemberService;

    }
    @Transactional
    public WorkspaceResponse createWorkspace(WorkspaceRequest workspaceRequest) {
        UUID currentUserId = getCurrentUserId();

        Workspace workspace = buildWorkspace(workspaceRequest, currentUserId);

        Workspace saved = workspaceRepository.save(workspace);

        workspaceMemberService.addOwnerAsAdmin(saved, saved.getOwnerUserID());

        return WorkspaceResponse.fromEntity(saved, "Workspace creado correctamente");
    }

    public List<WorkspaceResponse> getAllWorkspaces() {
        List<Workspace> workspaces = workspaceRepository.findAll();
        return workspaces.stream()
                .map(workspace -> WorkspaceResponse.fromEntity(workspace, "Workspaces obtenidos correctamente"))
                .toList();
    }

    public WorkspaceResponse getWorkspaceById(Integer id) {
        Workspace workspace = workspaceRepository.findById(id)
                .orElseThrow(() -> new WorkspaceNotFoundException(id));

        return WorkspaceResponse.fromEntity(workspace, "Workspace obtenido correctamente");
    }

    public WorkspaceResponse updateWorkspace(Integer id, WorkspaceRequest workspaceRequest) {

        Workspace workspace = findWorkspaceById(id);
        updateWorkspaceFields(workspace, workspaceRequest);

        workspaceRepository.save(workspace);

        return WorkspaceResponse.fromEntity(workspace, "Workspace Actulizado");
    }

    @Transactional
    public void deleteWorkspace(Integer id) {
        // Se usa el find porque antes de borrar el workspace toca borrar los usuarios y las tareas
        //Osea que depende de otros para ser borrada
        Workspace workspace = findWorkspaceOrThrow(id);
        // Eliminar el workspace
        workspaceRepository.delete(workspace);
    }


    // ========== ✅ AGREGADO: funcion pública para que otros services lo usen ==========
    public Workspace findWorkspaceOrThrow(Integer id) {
        return workspaceRepository.findById(id)
                .orElseThrow(() -> new WorkspaceNotFoundException(id));
    }

    // Metodos privados

    private Workspace buildWorkspace(WorkspaceRequest request, UUID currenteUserId){
        return Workspace.builder()
                .name(request.name())
                .description(request.description())
                .status(Workspace.WorkspaceStatus.ACTIVO)
                .data(request.data())
                .ownerUserID(currenteUserId)
                .build();
    }

    private UUID getCurrentUserId(){
        return UUID.fromString("00000000-0000-0000-0000-000000000001");
    }

    private Workspace findWorkspaceById(Integer id){
        return workspaceRepository.findById(id)
                .orElseThrow(() -> new WorkspaceNotFoundException(id));
    }

    private void updateWorkspaceFields(Workspace workspace, WorkspaceRequest workspaceRequest){
        workspace.setName(workspaceRequest.name());
        workspace.setDescription(workspaceRequest.description());
        if (workspaceRequest.status() != null) {
            workspace.setStatus(workspaceRequest.status());
        }
        workspace.setData(workspaceRequest.data());
    }



}
