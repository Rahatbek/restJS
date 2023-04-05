package web.service;

import web.model.User;

public interface UserService {
    Iterable<User> allUsers();
    void save(User user);
    void delete(User user);
    User getById(Long id);
}
