package backend.workspace.entity;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Entity
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "assignment")
public class Assignment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "name", nullable = false, length = 100)
    private String name;

    @Column(name = "description", length = 500)
    private String description;

    @Column(name = "due_date", nullable = false)
    private OffsetDateTime dueDate;

    @Enumerated(EnumType.ORDINAL)
    @Column(name = "status", nullable = false)
    private AssignmentStatus status;

    public enum AssignmentStatus{
        BORRADOR,
        PUBLICADO,
        CERRADO;

        // Devuelve el nombre del enum a Json para dar respuesta
        @JsonValue
        public String getValue(){
            return this.name();
        }

        // Recibe el valor del json y lo convierte en mayuscula para dar el response
        @JsonCreator
        public static AssignmentStatus fromString(String value){
            return AssignmentStatus.valueOf(value.toUpperCase());
        }
    }

    //Este campo en Java debe tratarse como un tipo JSON cuando se comunique con la base de datos.
    // Quiere decir que convierte de map a json y de json a map
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "rubric", columnDefinition = "jsonb", nullable = true)
    private Map<String, Object> rubric;

    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "settings", columnDefinition = "jsonb")
    private Map<String,Object> settings;


    //Relaciones

    //fetch para decir que no cargue las tareas a no ser que las necesite
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "workspace_id", nullable = false)
    private Workspace workspace;

    //el campo assignment en submissions tiene una fk
    @OneToMany(mappedBy = "assignment", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<Submission> submissions = new ArrayList<>();



}
