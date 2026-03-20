package backend.workspace.service;

import backend.workspace.dto.WorkspaceMember.WorkspaceMemberRequest;
import backend.workspace.dto.WorkspaceMember.WorkspaceMemberResponse;
import backend.workspace.entity.Workspace;
import backend.workspace.entity.WorkspaceMember;
import backend.workspace.repository.WorkspaceMemberRepository;
import backend.workspace.repository.WorkspaceRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.ArrayList;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

// Activa el mockito en JUnit 5
@ExtendWith(MockitoExtension.class)
class WorkspaceMemberServiceTest {

    //Crea los objetos simulados
    @Mock
    private WorkspaceMemberRepository workspaceMemberRepository;

    //Crea los objetos simulados, osea que va a simular la dependecia real
    //No toca la base de datos, ni comandos sql, y no usa el jpa real
    @Mock
    private WorkspaceRepository workspaceRepository;

    //Crea la clase real que se quiere probar e inyecta los moks automaticamente osea los que creamos
    @InjectMocks
    private WorkspaceMemberService workspaceMemberService;

    //es un metodo que se va a ejecutar como una prueba
    @Test
    // nombre del metodo, deberia crear el miembro cuando el codigo existe y el usuario no es miembro
    void shouldAddMemberWhenCodeExistAndUserIsNotMember(){
        UUID userId = UUID.randomUUID();

        //Se crea el objeto del worskpace para usarlo en el metodo de prueba
        Workspace workspace = Workspace.builder()
                .id(1)
                .name("Workspace de prueba")
                .description("Descripcion")
                .status(Workspace.WorkspaceStatus.ACTIVO)
                .members(new ArrayList<>())
                .build();

        //Creamos el input real
        //esto quiero decir que lo que le pasemos le estamos diciendo que me quiero unir al workspace del siguiente codigo y paso el userId
        //Este request es el dato que se le pasa al metodo real, osea que se pasa al servicio real
        WorkspaceMemberRequest request = new WorkspaceMemberRequest("ABC123", userId);

        // El when define el comportamiento del mock.
        // Quiere decir que cuando llamen a findByCode("ABC123"),
        // el mock del repositorio va a devolver un Optional que contiene el objeto workspace.
        when(workspaceRepository.findByCode("ABC123"))
                .thenReturn(Optional.of(workspace));

        when(workspaceMemberRepository.existsByWorkspaceIdAndUserId(1, userId))
                .thenReturn(false);

        WorkspaceMember savedMember = WorkspaceMember.builder()
                .id(10)
                .userId(userId)
                .role(WorkspaceMember.Role.MEMBER)
                .workspace(workspace)
                .build();

        when(workspaceMemberRepository.save(any(WorkspaceMember.class)))
                .thenReturn(savedMember);

        WorkspaceMemberResponse response = workspaceMemberService.addMember(request);

        //assertEquals compara el valor esperado con el real
        assertEquals(10, response.id());
        assertEquals(1, response.workspaceId());
        assertEquals(userId, response.userId());
        assertEquals(WorkspaceMember.Role.MEMBER, response.role());

        //verify Verifica que se haya llamado a un metodo
        verify(workspaceRepository).findByCode("ABC123");
        verify(workspaceMemberRepository).existsByWorkspaceIdAndUserId(1, userId);
        verify(workspaceMemberRepository).save(any(WorkspaceMember.class));
    }

}
