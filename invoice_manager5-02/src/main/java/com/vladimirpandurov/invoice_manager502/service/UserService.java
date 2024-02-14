package com.vladimirpandurov.invoice_manager502.service;

import com.vladimirpandurov.invoice_manager502.domain.User;
import com.vladimirpandurov.invoice_manager502.dto.UserDTO;

public interface UserService {

    UserDTO createUser(User user);

    UserDTO getUserByEmail(String email);

    void sendVerificationCode(UserDTO userDTO);

    UserDTO verifyCode(String email, String code);
}
