package backend.workspace.entity;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@Entity
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Table(name = "workspace_member", uniqueConstraints = {
        @UniqueConstraint(columnNames = {"workspace_id", "user_id"})
})
public class WorkspaceMember {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(name = "user_id", nullable = true)
    private UUID userId;

    @Enumerated(EnumType.ORDINAL)
    @Column(name = "role", nullable = false)
    private Role role;

    public enum Role{
        MEMBER,
        ADMIN;

        @JsonValue
        public String getName(){
            return this.name();
        }

        @JsonCreator
        public static Role fromString(String value){
            return Role.valueOf(value.toUpperCase());
        }
    }

    //fetch funciona para decir que no carga el workspace hasta que lo necesite
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "workspace_id", nullable = false)
    //Ahora guardamos all el objeto no solo el Id
    private Workspace workspace;
}
