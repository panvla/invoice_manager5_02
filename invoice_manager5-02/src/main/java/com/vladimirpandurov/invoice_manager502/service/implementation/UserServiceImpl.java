package com.vladimirpandurov.invoice_manager502.service.implementation;

import com.vladimirpandurov.invoice_manager502.domain.Role;
import com.vladimirpandurov.invoice_manager502.domain.User;
import com.vladimirpandurov.invoice_manager502.dto.UserDTO;
import com.vladimirpandurov.invoice_manager502.dtomapper.UserDTOMapper;
import com.vladimirpandurov.invoice_manager502.repository.RoleRepository;
import com.vladimirpandurov.invoice_manager502.repository.UserRepository;
import com.vladimirpandurov.invoice_manager502.service.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class UserServiceImpl implements UserService {

    private final UserRepository<User> userRepository;
    private final RoleRepository<Role> roleRepository;

    @Override
    public UserDTO createUser(User user) {
        return mapToUserDTO(this.userRepository.create(user));
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        return mapToUserDTO(this.userRepository.getUserByEmail(email));
    }

    @Override
    public void sendVerificationCode(UserDTO userDTO) {
        this.userRepository.sendVerificationCode(userDTO);
    }

    @Override
    public UserDTO verifyCode(String email, String code) {
        return UserDTOMapper.fromUser(this.userRepository.verifyCode(email, code));
    }

    private UserDTO mapToUserDTO(User user){
        return UserDTOMapper.fromUser(user, roleRepository.getRoleByUserId(user.getId()));
    }
}
