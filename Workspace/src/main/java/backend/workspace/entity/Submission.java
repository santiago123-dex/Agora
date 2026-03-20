package backend.workspace.entity;


import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.Map;
import java.util.UUID;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "submission")
public class Submission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "user_id", nullable = false)
    private UUID userId;

    @Column(name = "created_at", nullable = false)
    private OffsetDateTime createdAt;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "content", columnDefinition = "jsonb")
    private Map<String,Object>content;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "files", columnDefinition = "jsonb")
    private Map<String, Object> files;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "ai_result", columnDefinition = "jsonb")
    private Map<String, Object> aiResult;

    //Relaciones

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "assignment_id", nullable = false)
    private Assignment assignment;


    @PrePersist
    public void onCreate() {
        if(createdAt == null){
            createdAt = OffsetDateTime.now();
        }
    }


}
