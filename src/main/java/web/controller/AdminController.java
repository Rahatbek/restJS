package web.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import web.model.DTO.*;
import web.model.Role;
import web.model.User;
import web.repository.RoleRepository;
import web.service.UserServiceImpl;

import java.util.*;

@Controller
@RequestMapping("/admin")
public class AdminController {
    private final UserServiceImpl userService;
    private final RoleRepository roleRepository;

    public AdminController(UserServiceImpl userService, RoleRepository roleRepository) {
        this.userService = userService;
        this.roleRepository = roleRepository;
    }

    @GetMapping
    public ModelAndView allUsers() {
        List<User> users = new ArrayList<>();
        userService.allUsers().forEach(users::add);
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("admin");
        modelAndView.addObject("usersList", users);
        return modelAndView;
    }

    @GetMapping("/add")
    public String addPage() {
        return "addUser";
    }

    @PostMapping(value = "/add")
    public String addUser(@ModelAttribute("user") User user) {
        userService.save(user);
        return "redirect:/admin";
    }

    @GetMapping("/edit/{id}")
    public ModelAndView editPage(@PathVariable("id") long id) {
        User user = userService.getById(id);
        ModelAndView modelAndView = new ModelAndView();
        modelAndView.setViewName("adminEditUser");
        modelAndView.addObject("user", user);
        String[] rolelist = {"ADMIN", "USER"};
        modelAndView.addObject("rolelist", rolelist);
        return modelAndView;
    }

    @PostMapping("/edit")
    public String editUser(@ModelAttribute("user") UserDTO userDTO,
                           @RequestParam(value = "sel_roles", required = false) String[] sel_roles,
                           BindingResult result
    ) {
        if (result.hasErrors()) {

        }
        User user = new User(userDTO);
        Set<Role> Setroles = new HashSet<>();
        if (sel_roles != null) {
            for (String st : sel_roles) {
                if (st.equals("ADMIN")) {
                    Optional<Role> findRole = roleRepository.findByname("ADMIN");
                    if (!findRole.isPresent()) {
                        Role role_admin = new Role(1L, "ADMIN");
                        roleRepository.save(role_admin);
                        Setroles.add(role_admin);
                    } else {
                        Setroles.add(findRole.get());
                    }
                }
                if (st.equals("USER")) {
                    Optional<Role> findRole = roleRepository.findByname("USER");
                    if (!findRole.isPresent()) {
                        Role role_user = new Role(2L, "USER");
                        roleRepository.save(role_user);
                        Setroles.add(role_user);
                    } else {
                        Setroles.add(findRole.get());
                    }
                }
            }
            user.setRoles(Setroles);
        }
        userService.save(user);
        return "redirect:/admin";
    }

    @GetMapping("/delete/{id}")
    public String deleteUser(@PathVariable("id") long id) {
        User user = userService.getById(id);
        userService.delete(user);
        return "redirect:/admin";
    }


}
