package backend.workspace.exception;


import backend.workspace.exception.Assignment.AssignmentExpiredException;
import backend.workspace.exception.Assignment.AssignmentNotFoundException;
import backend.workspace.exception.Submission.SubmissionAlreadyExistException;
import backend.workspace.exception.Submission.SubmissionNotFoundException;
import backend.workspace.exception.Workspace.InvalidWorkspaceException;
import backend.workspace.exception.Workspace.WorkspaceNotFoundException;
import backend.workspace.exception.WorkspaceMember.MemberAlreadyExistException;
import backend.workspace.exception.WorkspaceMember.MemberNotFoundException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import lombok.extern.slf4j.Slf4j;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

// Lugar donde vamos a procesar todos los errores
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    @ExceptionHandler(WorkspaceNotFoundException.class)
    // Se pone el webRequest para obtener la URL solicitada osea el endpoint
    public ResponseEntity<ErrorResponse> handleWorkspaceNotFound(WorkspaceNotFoundException ex, WebRequest request){
      ErrorResponse errorResponse = ErrorResponse.of(
              HttpStatus.NOT_FOUND.value(),
              ex.getMessage(),
              "Not Found",
              getPath(request)
      );
      
      return ResponseEntity
              .status(HttpStatus.NOT_FOUND)
              .body(errorResponse);
    }

    @ExceptionHandler(InvalidWorkspaceException.class)
    public ResponseEntity<ErrorResponse> handleInvalidWorkspace(InvalidWorkspaceException ex, WebRequest request){
        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.BAD_REQUEST.value(),
                ex.getMessage(),
                "Bad Request",
                getPath(request)
        );
        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(errorResponse);
     }

     @ExceptionHandler(MemberAlreadyExistException.class)
     public ResponseEntity<ErrorResponse> handleMemberAlreadyExists(MemberAlreadyExistException ex, WebRequest request){
        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                ex.getMessage(),
                "Conflict",
                getPath(request)
        );

         return ResponseEntity
                 .status(HttpStatus.CONFLICT)
                 .body(errorResponse);
     }

     @ExceptionHandler(MemberNotFoundException.class)
     public ResponseEntity<ErrorResponse> handleMemberNotFound(MemberNotFoundException ex, WebRequest request){
        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.NOT_FOUND.value(),
                ex.getMessage(),
                "Not found",
                getPath(request)
        );

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(errorResponse);
    }

     @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericExeception(Exception ex, WebRequest request){
        log.error("Unhandled exception on path {}", getPath(request), ex);
        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal server error",
                "Ocurrió un error inesperado. Por favor contacte al administrador.",
                getPath(request)
        );

        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(errorResponse);
     }

     // Este metodo se ejecuta automaticamente cuando el @Valid falla
     @ExceptionHandler(MethodArgumentNotValidException.class)
     /*
     * Se pone el MethodArgumentNotValidException.class para que solo se ejecute cuando el @Valid falla
     * Esta contiene a detalle sobre las validaciones que fallaron
     * Se pone WebRequest para obtener la URL solicitada osea el endpoint
     * */
     public ResponseEntity<ErrorResponse> handleValidationErrors(MethodArgumentNotValidException ex, WebRequest request){
        //Aca vamos a almacenar los errores
         Map<String, String> errors = new HashMap<>();
         /*
         * El getBindingResult() nos da el resultado de todas las validaciones
         * getAllErrors() nos da todos los errores
         * forEach(error ->) recorre todos los errores
         * */
         ex.getBindingResult().getAllErrors().forEach(error ->{
             /*
             * Obtenemos el nombre del campo que fallóString fieldName = ((FieldError)error).getField();
             * */
             String fieldName = ((FieldError)error).getField();
             // Entrega el mensaje de error definido en la anotación de validacion del DTO o Entity
             String errorMessage = error.getDefaultMessage();

             errors.put(fieldName, errorMessage);
         });

            ErrorResponse errorResponse = ErrorResponse.builder()
                    .timestamp(LocalDateTime.now())
                    .status(HttpStatus.BAD_REQUEST.value())
                    .error("Validation Failed")
                    .message("Errores de validacion en los campos")
                    .path(getPath(request))
                    .validationErrors(errors)
                    .build();

                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);

     }

     //Exception De Assignment not found

    @ExceptionHandler(AssignmentNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleAssignmentNotFound(AssignmentNotFoundException ex, WebRequest request) {
        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.NOT_FOUND.value(),
                "Not Found",
                ex.getMessage(),
                getPath(request)
        );

        return ResponseEntity
                .status(HttpStatus.NOT_FOUND)
                .body(errorResponse);
    }

    // Execption de Submission Not Found

    @ExceptionHandler(SubmissionNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleSubmissionNotFound(SubmissionNotFoundException ex, WebRequest request){
         ErrorResponse errorResponse = ErrorResponse.of(
                 HttpStatus.NOT_FOUND.value(),
                 "Not Found",
                 ex.getMessage(),
                 getPath(request)
         );

         return ResponseEntity
                 .status(HttpStatus.NOT_FOUND)
                 .body(errorResponse);
    }

    // Exception de Submission Already Exist
    //Se usa el .class para decirle a Java que lo interprete como una clase
    @ExceptionHandler(SubmissionAlreadyExistException.class)
    public ResponseEntity<ErrorResponse> handleSubmissionAlreadyExist(SubmissionAlreadyExistException ex, WebRequest request){
        ErrorResponse errorResponse = ErrorResponse.of(
                HttpStatus.CONFLICT.value(),
                "Conflict",
                ex.getMessage(),
                getPath(request)
        );

        return ResponseEntity
                .status(HttpStatus.CONFLICT)
                .body(errorResponse);
    }

    // Exception de AssignmentExpired
    @ExceptionHandler(AssignmentExpiredException.class)
    public ResponseEntity<ErrorResponse> handleAssignmentExpired(AssignmentExpiredException ex, WebRequest request){
         ErrorResponse errorResponse = ErrorResponse.of(
                 HttpStatus.BAD_REQUEST.value(),
                 "Bad Request",
                 ex.getMessage(),
                 getPath(request)
         );

         return ResponseEntity
                 .status(HttpStatus.BAD_REQUEST)
                 .body(errorResponse);
    }


    // Se usa para decir que solo vamos a pasar la URL solicitada osea el endpoint
    private String getPath(WebRequest request){

        return request.getDescription(false).replace("uri=", "");
    }
}
