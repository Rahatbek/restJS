package web.config;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import web.model.Role;
import web.model.User;
import web.service.RoleService;
import web.service.UserService;

import javax.annotation.PostConstruct;
import java.util.HashSet;
import java.util.Set;

@Component
public class DataInitialaizer {
    private UserService userService;
    private RoleService roleService;

    public DataInitialaizer(UserService userService, RoleService roleService) {
        this.userService = userService;
        this.roleService = roleService;
    }

    @PostConstruct
    public void Init() {
        Set<Role> allRoles = new HashSet<>();
        allRoles.add(new Role("ADMIN"));
        allRoles.add(new Role("USER"));
        Set<Role> userRole = new HashSet<>();
        userRole.add(new Role("USER"));
        Set<Role> adminRole = new HashSet<>();
        adminRole.add(new Role("ADMIN"));
        roleService.createRoles(allRoles);
        User admin = new User("admin", "admin", 33, "admin@mail.ru", "admin",allRoles);
//        admin.setRoles("ADMIN, USER");
            userService.createUser(admin);
        User user = new User("user", "user", 10, "user@mail.ru", "user", userRole);
//        user.setRoles("USER");
        userService.createUser(user);
        User user1 = new User("user1", "user1", 20, "user1@mail.ru", "user1", userRole);
//        user1.setRoles("USER");
        userService.createUser(user1);
        User user2 = new User("user2", "user2", 30, "user2@mail.ru", "user2", userRole);
//        user2.setRoles("USER");
        userService.createUser(user2);
    }
}
