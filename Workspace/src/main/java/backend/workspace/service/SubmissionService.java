package backend.workspace.service;

import backend.workspace.dto.Submission.SubmissionRequest;
import backend.workspace.dto.Submission.SubmissionResponse;
import backend.workspace.entity.Assignment;
import backend.workspace.entity.Submission;
import backend.workspace.exception.Assignment.AssignmentExpiredException;
import backend.workspace.exception.Submission.SubmissionAlreadyExistException;
import backend.workspace.exception.Submission.SubmissionNotFoundException;
import backend.workspace.repository.SubmissionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

@Service
// Indica que el servicio es de solo lectura
@Transactional(readOnly = true)
public class SubmissionService {

    private final SubmissionRepository submissionRepository;
    private final AssignmentService assignmentService;

    public SubmissionService(SubmissionRepository submissionRepository, AssignmentService assignmentService) {
        this.submissionRepository = submissionRepository;
        this.assignmentService = assignmentService;
    }

    @Transactional
    public SubmissionResponse submitAssignment(SubmissionRequest request) {

        // Evitamos dos consultas y primero declaramos la variable, y luego dependiendo del id lo guardamos en la variable
        Assignment assignment = assignmentService.findAssignmentOrThrow(request.assignmentId());
        validateAssignmentNotExpired(assignment);
        validateSubmissionNotExists(request.userId(), request.assignmentId());

        Submission submission = Submission.builder()
                .userId(request.userId())
                .content(request.content())
                .files(request.files())
                .build();

        submission.setAssignment(assignment);
        assignment.getSubmissions().add(submission);

        // Utilizamos la instacia que retorna el save porque jpa puede devolver una entidad administrada
        // diferente a la original asi que con esta garantizamos que usamos la version persistida
        Submission saved = submissionRepository.save(submission);

        return SubmissionResponse.fromEntity(saved);
    }

    // Devuelve la lista de tareas entregadas para una tarea en especifico
    public List<SubmissionResponse> getSubmissionsByAssignment(Integer assignmentId) {

        assignmentService.findAssignmentOrThrow(assignmentId);

        return submissionRepository.findByAssignmentId(assignmentId)
                .stream()
                .map(SubmissionResponse::fromEntity)
                .toList();
    }

    // Devuelve la lista de tareas que ha enviado un usuario en especifico
    public List<SubmissionResponse> getSubmissionByUser(UUID userId) {

        return submissionRepository.findByUserId(userId)
                .stream()
                .map(SubmissionResponse::fromEntity)
                .toList();
    }

    //Devuelve la lista de tareas dependiendo del id
    public SubmissionResponse getSubmissionById(Integer id) {

        // Obtiene la entidad Submission correspondiente al id desde la base de datos.
        // Si no existe, el métod findSubmissionOrThrow lanza una excepción.
        Submission submission = findSubmissionOrThrow(id);
        return SubmissionResponse.fromEntity(submission);

    }

    //Update Submission
    @Transactional
    public SubmissionResponse updateSubmission(Integer id, SubmissionRequest request) {

        Submission submission = findSubmissionOrThrow(id);

        Assignment assignment = submission.getAssignment();
        validateAssignmentNotExpired(assignment);

        submission.setContent(request.content());
        submission.setFiles(request.files());

        Submission updated = submissionRepository.save(submission);

        return SubmissionResponse.fromEntity(updated);

    }

    @Transactional
    public void deleteSubmission(Integer id){
        Submission submission = findSubmissionOrThrow(id);
        //Se obtiene la tarea a la que pertenece las submission
        Assignment assignment = submission.getAssignment();
        assignment.getSubmissions().remove(submission);
        submissionRepository.delete(submission);
    }

    // Metodos privados

    // verifica que no haya expirado la enviada
    private void validateAssignmentNotExpired(Assignment assignment) {
        if (assignment.getDueDate().isBefore(OffsetDateTime.now()) || assignment.getStatus() == Assignment.AssignmentStatus.CERRADO) {
            throw new AssignmentExpiredException(assignment.getId());
        }
    }

    // Verifica si el usuario ya entrego esa tarea para que no se vaya duplicada
    private void validateSubmissionNotExists(UUID userId, Integer assignmentId) {
        if (submissionRepository.existsByAssignmentIdAndUserId(assignmentId, userId)) {
            throw new SubmissionAlreadyExistException(userId, assignmentId);
        }
    }

    // Comprobar que exista el Submission
    private Submission findSubmissionOrThrow(Integer id){
        return submissionRepository.findById(id)
                .orElseThrow(() -> new SubmissionNotFoundException(id));
    }


}
