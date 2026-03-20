package backend.workspace;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
// Habilita la programación de tareas para el servicio de workspace, osea que ayuda a ejecutar el Scheduled que se encuentra en el AssignmentService para actualizar el estado de las tareas a cerrado cuando ya paso la fecha de vencimiento
@EnableScheduling
public class WorkspaceApplication {

    public static void main(String[] args) {
        SpringApplication.run(WorkspaceApplication.class, args);
    }

}
