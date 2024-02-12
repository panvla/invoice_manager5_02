package com.vladimirpandurov.invoice_manager502.repository;

import com.vladimirpandurov.invoice_manager502.domain.Role;

import java.util.Collection;
import java.util.stream.Collectors;

public interface RoleRepository <T extends Role> {

    T create(T data);
    Collection<T> list(int page, int pageSize);
    T get(Long id);
    T update(T data);
    Boolean delete(Long id);

    void addRoleToUser(Long userId, String roleName);
    Role getRoleByUserId(Long userId);
    Role getRoleByUserEmail(String email);
    void updateUserRole(Long userId, String roleName);
}
