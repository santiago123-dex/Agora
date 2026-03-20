package backend.workspace.service;

import backend.workspace.dto.Assignment.AssignmentRequest;
import backend.workspace.dto.Assignment.AssignmentResponse;
import backend.workspace.entity.Assignment;
import backend.workspace.entity.Workspace;
import backend.workspace.exception.Assignment.AssignmentNotFoundException;
import backend.workspace.exception.Workspace.WorkspaceNotFoundException;
import backend.workspace.repository.AssignmentRepository;
import backend.workspace.repository.WorkspaceRepository;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;

@Service
public class AssignmentService {

    private final AssignmentRepository assignmentRepository;
    private final WorkspaceRepository workspaceRepository;
    private final WorkspaceService workspaceService;

    public AssignmentService(AssignmentRepository assignmentRepository, WorkspaceRepository workspaceRepository, WorkspaceService workspaceService){
        this.assignmentRepository = assignmentRepository;
        this.workspaceRepository = workspaceRepository;
        this.workspaceService = workspaceService;
    }

    @Transactional
    public AssignmentResponse createAssignment(AssignmentRequest request){

        //Buscamos el objeto completo
        Workspace workspace = workspaceService.findWorkspaceOrThrow(request.workspaceId());

        Assignment assignment = Assignment.builder()
                .name(request.name())
                .description(request.description())
                .dueDate(request.dueDate())
                .status(Assignment.AssignmentStatus.PUBLICADO)
                .rubric(request.rubric())
                .settings(request.settings())
                .build();

        // ====================== Estas son relaciones Bidireccionales ===================== //

        //Guardamos el objeto completo osea los datos de assignment con el objeto de workspace
        assignment.setWorkspace(workspace);
        workspace.getAssignments().add(assignment);

        Assignment saved = assignmentRepository.save(assignment);

        return AssignmentResponse.fromEntity(saved);

    }

    // Se obtienen las tareas segun el workspace, pero antes se valida que el workspace exista, 
    // si no existe se lanza una excepcion,
    //  luego se buscan las tareas por el id del workspace y se actualiza su estado a cerrado si ya paso la fecha de vencimiento,
    //  por ultimo se convierten a response y se devuelven
    @Transactional
    public List<AssignmentResponse> getAssignmentsByWorkspace(Integer workspaceId){
        validateWorkspace(workspaceId);

        return assignmentRepository.findByWorkspaceId(workspaceId)
                .stream()
                // .map(assignment -> updateStatusIfExpired(assignment)) esta seria la forma larga
                .map(this::updateStatusIfExpired)
                .map(AssignmentResponse::fromEntity)
                .toList();
    }

    // trae las tareas de un workspace dependiendo que status le digamos
    public List<AssignmentResponse> getAssignmentsByWorkspaceAndStatus(Integer workspaceId, Assignment.AssignmentStatus status){

        validateWorkspace(workspaceId);

        return  assignmentRepository.findByWorkspaceIdAndStatus(workspaceId, status)
                .stream()
                .map(this::updateStatusIfExpired)
                .map(AssignmentResponse::fromEntity)
                .toList();

    }

    @Transactional
    public AssignmentResponse getAssignmentById(Integer id){
        //Comprobamos si esta la tarea
        Assignment assignment = findAssignmentById(id);
        updateStatusIfExpired(assignment);

        return AssignmentResponse.fromEntity(assignment);
    }

    @Transactional
    public AssignmentResponse updateAssignment(Integer id, AssignmentRequest request){

        Assignment assignment = findAssignmentById(id);

        assignment.setName(request.name());
        assignment.setDescription(request.description());
        assignment.setDueDate(request.dueDate());
        assignment.setRubric(request.rubric());
        assignment.setSettings(request.settings());

        // Le devolvemos a assignmnet el estado verificado
        assignment = updateStatusIfExpired(assignment);
        assignmentRepository.save(assignment);

        return AssignmentResponse.fromEntity(assignment);
    }

    @Transactional
    public void deleteAssignment(Integer id){

        Assignment assignment = findAssignmentOrThrow(id);

        //traemos el workspace del assignment
        Workspace workspace = assignment.getWorkspace();
        workspace.getAssignments().remove(assignment);

        // Gracias a cascade = ALL y orphanRemoval = true,
        // se borran automáticamente todas las submissions
        assignmentRepository.delete(assignment);
    }

    // Se ejecuta cada hora porque el segundo y el minuto se define en 0
    @Scheduled(cron = "0 0 * * * *")
    @Transactional
    public void closeExpiredAssignments(){
        // Buscamos todas las tareas que esten publicadas y que su fecha de vencimiento sea anterior a la fecha actual
        List<Assignment> expiredAssignments = assignmentRepository.findByDueDateBeforeAndStatus(OffsetDateTime.now(),
                Assignment.AssignmentStatus.PUBLICADO);

        // Recorremos todas la tareas y actualizamos su estado a CERRADO
        expiredAssignments.forEach( assignment -> { assignment.setStatus(Assignment.AssignmentStatus.CERRADO);
            assignmentRepository.save(assignment);
        });
    }

    /*Metodo para actualizar el Status a CERRADO por si la fecha ya se acabo*/
    @Transactional
    public Assignment updateStatusIfExpired(Assignment assignment){
        if (assignment.getDueDate().isBefore(OffsetDateTime.now()) && assignment.getStatus() == Assignment.AssignmentStatus.PUBLICADO){

            assignment.setStatus(Assignment.AssignmentStatus.CERRADO);
            assignment = assignmentRepository.save(assignment);
        }
        return assignment;
    }

    //Metodo para validar si existe
    public Assignment findAssignmentOrThrow(Integer id) {
        return assignmentRepository.findById(id)
                .orElseThrow(() -> new AssignmentNotFoundException(id));
    }

    //Metodos privados
    private void validateWorkspace(Integer workspcaeId){
        if(!workspaceRepository.existsById(workspcaeId)){
            throw new WorkspaceNotFoundException(workspcaeId);
        }
    }

    private Assignment findAssignmentById(Integer id){
        return assignmentRepository.findById(id)
                .orElseThrow(() -> new AssignmentNotFoundException(id));
    }


}
