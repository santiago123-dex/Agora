package backend.workspace.controller;


import backend.workspace.dto.Submission.SubmissionRequest;
import backend.workspace.dto.Submission.SubmissionResponse;

import backend.workspace.service.SubmissionService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/submission")
public class SubmissionController {

    private final SubmissionService submissionService;

    // Endpoint para entregar una tarea
    @PostMapping()
    public ResponseEntity<SubmissionResponse> submitAssignment(@Valid @RequestBody SubmissionRequest request){

        SubmissionResponse response =  submissionService.submitAssignment(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // Endpoint para obtener las entregas de una tarea en especifico
    @GetMapping("/assignment/{assignmentId}")
    public ResponseEntity<List<SubmissionResponse>> getSubmissionsByAssignment(@PathVariable Integer assignmentId){

        List<SubmissionResponse> submissionResponse = submissionService.getSubmissionsByAssignment(assignmentId);
        return ResponseEntity.ok(submissionResponse);

    }

    @GetMapping("/user/{userId}")
    public ResponseEntity<List<SubmissionResponse>> getSubmissionByUser(@PathVariable UUID userId){

        List<SubmissionResponse> submissions = submissionService.getSubmissionByUser(userId);
        return ResponseEntity.ok(submissions);

    }

    @GetMapping("/{id}")
    public ResponseEntity<SubmissionResponse> getSubmissionById(@PathVariable Integer id){

        SubmissionResponse response = submissionService.getSubmissionById(id);
        return ResponseEntity.ok(response);

    }

    @PutMapping("/{id}")
    public ResponseEntity<SubmissionResponse> updateSubmission(@PathVariable Integer id, @Valid @RequestBody SubmissionRequest request){

        SubmissionResponse response = submissionService.updateSubmission(id, request);
        return ResponseEntity.ok(response);

    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteSubmission(@PathVariable Integer id){
        submissionService.deleteSubmission(id);
        return ResponseEntity.noContent().build();
    }

}
