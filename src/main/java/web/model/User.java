package web.model;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import web.model.DTO.*;

import javax.persistence.*;
import java.util.*;

@Entity
@Table(name = "t_users")
public class User implements UserDetails {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String name;
    private String lastname;
    private byte age;
    private String city;
    private String password;
    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles;
    @Transient
    private String[] sel_roles;

    public User(UserDTO userDTO) {
        this.id = userDTO.getId();
        this.name = userDTO.getName();
        this.lastname = userDTO.getLastname();
        this.age = userDTO.getAge();
        this.city = userDTO.getCity();
        this.password = userDTO.getPassword();
    }

    public String[] getSel_roles_string() {
        return sel_roles;
    }

    public String[] getSel_roles() {
        String[] str_roles = new String[getRoles().size()];
        int i = 0;
        for (Role role : getRoles()){
            str_roles[i++] = role.getName();
        }
        return  str_roles;
    }

    public void setSel_roles(String[] sel_roles) {
        this.sel_roles = sel_roles;
    }

    public Set<Role> getRoles() {
        return roles;
    }

    public void setRoles(Set<Role> roles) {
        this.roles = roles;
    }

    public void setRoles(String[] roles) {

    }

    public User() {
    }

    public Long getId() {
        return id;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return roles;
    }

    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return name;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User(String name, String lastname, byte age, String city) {
        this.name = name;
        this.lastname = lastname;
        this.age = age;
        this.city = city;
    }

    public User(Long id, String name, String lastname, byte age, String city, String password) {
        this.id = id;
        this.name = name;
        this.lastname = lastname;
        this.age = age;
        this.city = city;
        this.password = password;
    }

    public User(Long id, String name, String lastname, byte age, String city, String password, String[] roles) {
        this.id = id;
        this.name = name;
        this.lastname = lastname;
        this.age = age;
        this.city = city;
        this.password = password;
        //this.roles = roles;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getLastname() {
        return lastname;
    }

    public void setLastname(String lastname) {
        this.lastname = lastname;
    }

    public byte getAge() {
        return age;
    }

    public void setAge(byte age) {
        this.age = age;
    }

    public String getCity() {
        return city;
    }

    public void setCity(String city) {
        this.city = city;
    }
}
