package backend.workspace.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.time.LocalDateTime;
import java.util.Map;

@Builder
//No se incluyen los campos que sean null en el JSON
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        LocalDateTime timestamp,
        // Status code
        int status,
        String error,
        String message,
        //Endpoint donde ocurrio eso
        String path,
        //Se usa cuando falla el @Valid del controller
        Map<String, String> validationErrors
) {
    public static ErrorResponse of(int status, String message, String error, String path){
        //No se pone el new porque es un objeto controlado
        return ErrorResponse.builder()
                .timestamp(LocalDateTime.now())
                .status(status)
                .error(error)
                .message(message)
                .path(path)
                .build();
    }
}
