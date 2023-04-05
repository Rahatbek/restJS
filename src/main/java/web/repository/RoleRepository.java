package web.repository;

import org.springframework.data.repository.CrudRepository;
import web.model.Role;
import web.model.User;

import java.util.Optional;

public interface RoleRepository  extends CrudRepository<Role, Long> {
    Optional<Role> findByname(String name);
}

