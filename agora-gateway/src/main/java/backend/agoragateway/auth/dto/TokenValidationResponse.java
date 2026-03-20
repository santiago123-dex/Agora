package backend.agoragateway.auth.dto;

public record TokenValidationResponse(
        String user_id,
        String session_id
) {
}

