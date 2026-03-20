package backend.workspace.repository;

import backend.workspace.entity.Workspace;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface WorkspaceRepository extends JpaRepository<Workspace, Integer> {

    @Query(value = "select * from workspace w where w.data ->> 'code' = :code", nativeQuery = true)
    Optional<Workspace> findByCode(@Param("code") String code);
}
