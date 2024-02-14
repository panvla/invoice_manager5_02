package com.vladimirpandurov.invoice_manager502.service;

import com.vladimirpandurov.invoice_manager502.domain.Role;

public interface RoleService {

    Role getRoleByUserId(Long userId);

}
