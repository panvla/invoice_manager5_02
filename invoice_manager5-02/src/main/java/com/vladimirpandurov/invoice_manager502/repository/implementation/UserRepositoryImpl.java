package com.vladimirpandurov.invoice_manager502.repository.implementation;

import com.vladimirpandurov.invoice_manager502.domain.User;
import com.vladimirpandurov.invoice_manager502.domain.UserPrincipal;
import com.vladimirpandurov.invoice_manager502.dto.UserDTO;
import com.vladimirpandurov.invoice_manager502.exception.ApiException;
import com.vladimirpandurov.invoice_manager502.repository.RoleRepository;
import com.vladimirpandurov.invoice_manager502.repository.UserRepository;
import com.vladimirpandurov.invoice_manager502.rowmapper.UserRowMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.data.relational.core.sql.In;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.jdbc.core.namedparam.SqlParameterSource;
import org.springframework.jdbc.support.GeneratedKeyHolder;
import org.springframework.jdbc.support.KeyHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.util.*;

import static com.vladimirpandurov.invoice_manager502.enumeration.RoleType.ROLE_USER;
import static com.vladimirpandurov.invoice_manager502.enumeration.VerificationType.ACCOUNT;
import static com.vladimirpandurov.invoice_manager502.query.UserQuery.*;
import static org.apache.commons.lang3.RandomStringUtils.randomAlphabetic;
import static org.apache.commons.lang3.time.DateFormatUtils.format;
import static org.apache.commons.lang3.time.DateUtils.addDays;

@Repository
@RequiredArgsConstructor
@Slf4j
public class UserRepositoryImpl implements UserRepository<User>, UserDetailsService {

    private static final String DATA_FORMAT = "yyyy-MM-dd hh:mm:ss";
    private final NamedParameterJdbcTemplate jdbc;
    private final RoleRepository roleRepository;
    private final BCryptPasswordEncoder encoder;

    @Override
    public User create(User user) {
        if(getEmailCount(user.getEmail().trim().toLowerCase()) > 0) throw new ApiException("Email already in use. Please use a different email and try again");
        try{
            KeyHolder holder = new GeneratedKeyHolder();
            SqlParameterSource parameters = getSqlParameterSource(user);
            jdbc.update(INSERT_USER_QUERY, parameters, holder);
            user.setId(Objects.requireNonNull(holder.getKey().longValue()));
            roleRepository.addRoleToUser(user.getId(), ROLE_USER.name());
            String verificationUrl = getVerificationUrl(UUID.randomUUID().toString(), ACCOUNT.getType());
            jdbc.update(INSERT_ACCOUNT_VERIFICATION_URL_QUERY, Map.of("userId", user.getId(), "url", verificationUrl));
            //emailService.sendEmail();
            user.setEnabled(true);
            user.setNotLocked(true);
            return user;
        }catch (Exception exception){
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public Collection<User> list(int page, int pageSize) {
        return null;
    }

    @Override
    public User get(Long id) {
        return null;
    }

    @Override
    public User update(User data) {
        return null;
    }

    @Override
    public Boolean delete(Long id) {
        return null;
    }

    @Override
    public User getUserByEmail(String email) {
        try{
            User user = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());
            return user;
        }catch (EmptyResultDataAccessException exception){
            log.error("No user found by email");
            throw new ApiException("No user found by email: " + email);
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public void sendVerificationCode(UserDTO userDTO) {
        String expirationDate = format(addDays(new Date(), 1), DATA_FORMAT);
        String verificationCode = randomAlphabetic(8).toUpperCase();
        try{
            jdbc.update(DELETE_VERIFICATION_CODE_BY_USER_ID, Map.of("id", userDTO.getId()));
            jdbc.update(INSERT_VERIFICATION_CODE_QUERY, Map.of("user_id", userDTO.getId(), "code", verificationCode, "expirationDate", expirationDate));
            //sendSms()
            log.info("Verification CODE: {}", verificationCode);
        }catch (Exception exception){
            log.error(exception.getMessage());
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    @Override
    public User verifyCode(String email, String code) {
        if(isVerificationCodeExpired(code)) throw new ApiException("This code has expired. Please login again.");
        try{
            User userByCode = jdbc.queryForObject(SELECT_USER_BY_USER_CODE_QUERY, Map.of("code", code), new UserRowMapper());
            User userByEmail = jdbc.queryForObject(SELECT_USER_BY_EMAIL_QUERY, Map.of("email", email), new UserRowMapper());
            if(userByCode.getEmail().equalsIgnoreCase(userByEmail.getEmail())){
                jdbc.update(DELETE_CODE_BY_CODE, Map.of("code", code));
                return userByCode;
            }else{
                throw new ApiException("Code is invalid. Please try again");
            }
        }catch (EmptyResultDataAccessException exception){
            throw new ApiException("Unable to find record");
        }catch (Exception exception){
            throw new ApiException("An error occurred. Please try again.");
        }
    }

    private Boolean isVerificationCodeExpired(String code){
        try{
            return jdbc.queryForObject(SELECT_CODE_EXPIRATION_QUERY, Map.of("code", code), Boolean.class);
        }catch (EmptyResultDataAccessException exception){
            throw new ApiException("This code is not valid. Please login again.");
        }catch (Exception exception){
            log.info(exception.getMessage());
            throw new ApiException("An error occurred. Please try again.");
        }
    }


    private String getVerificationUrl(String key, String type){
        return ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/verify/" + type + "/" + key).toUriString();
    }

    private SqlParameterSource getSqlParameterSource(User user){
        return new MapSqlParameterSource()
                .addValue("firstName", user.getFirstName())
                .addValue("lastName", user.getLastName())
                .addValue("email", user.getEmail())
                .addValue("password", encoder.encode(user.getPassword()));
    }

    private Integer getEmailCount(String email) {
        return jdbc.queryForObject(COUNT_USER_EMAIL_QUERY, Map.of("email", email), Integer.class);
    }

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = getUserByEmail(email);
        if(user == null){
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        }else{
            UserPrincipal userPrincipal = new UserPrincipal(user, this.roleRepository.getRoleByUserId(user.getId()));
            return userPrincipal;
        }
    }
}
