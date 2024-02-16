package com.vladimirpandurov.invoice_manager502.resource;

import com.vladimirpandurov.invoice_manager502.domain.HttpResponse;
import com.vladimirpandurov.invoice_manager502.domain.User;
import com.vladimirpandurov.invoice_manager502.domain.UserPrincipal;
import com.vladimirpandurov.invoice_manager502.dto.UserDTO;
import com.vladimirpandurov.invoice_manager502.dtomapper.UserDTOMapper;
import com.vladimirpandurov.invoice_manager502.exception.ApiException;
import com.vladimirpandurov.invoice_manager502.form.LoginForm;
import com.vladimirpandurov.invoice_manager502.provider.TokenProvider;
import com.vladimirpandurov.invoice_manager502.service.RoleService;
import com.vladimirpandurov.invoice_manager502.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.net.URI;
import java.time.LocalDateTime;
import java.util.Map;

import static com.vladimirpandurov.invoice_manager502.utils.ExceptionUtils.processError;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.authentication.UsernamePasswordAuthenticationToken.unauthenticated;

@RestController
@RequestMapping("/user")
@RequiredArgsConstructor
@CrossOrigin
@Slf4j
public class UserResource {

    private final AuthenticationManager authenticationManager;
    private final UserService userService;
    private final RoleService roleService;
    private final TokenProvider tokenProvider;
    private final HttpServletRequest request;
    private final HttpServletResponse response;
    private static final String TOKEN_PREFIX = "Bearer ";

    @PostMapping("/register")
    public ResponseEntity<HttpResponse> saveUser(@RequestBody @Valid User user){
        UserDTO userDTO = this.userService.createUser(user);
        return ResponseEntity.created(getUri(userDTO.getId())).body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .data(Map.of("user", userDTO))
                .message("User created")
                .build()
        );
    }
    @PostMapping("/login")
    public ResponseEntity<HttpResponse> login(@RequestBody @Valid LoginForm loginForm){
        authenticationManager.authenticate(unauthenticated(loginForm.getEmail(), loginForm.getPassword()));
        Authentication authentication = authenticate(loginForm.getEmail(), loginForm.getPassword());
        UserDTO userDTO = getAuthenticatedUser(authentication);
        return userDTO.isUsingMfa() ? sendVerificationCode(userDTO) : sendResponse(userDTO);
    }
    @GetMapping("/verify/code/{email}/{code}")
    public ResponseEntity<HttpResponse> verifyCode(@PathVariable("email") String email, @PathVariable("code") String code){
        UserDTO userDTO = this.userService.verifyCode(email, code);
        return sendResponse(userDTO);
    }
    @GetMapping("/profile")
    public ResponseEntity<HttpResponse> profile(Authentication authentication){
        UserDTO userDTO = this.userService.getUserByEmail(authentication.getName());
        log.info(authentication.getName());
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("user", userDTO))
                .message("Profile Retrieved")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build()
        );
    }
    @GetMapping("/resetpassword/{email}")
    public ResponseEntity<HttpResponse> resetPassword(@PathVariable("email") String email){
        userService.resetPassword(email);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .message("Email sent. Please chack your email to reset your password")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build()
        );
    }
    @GetMapping("/verify/password/{key}")
    public ResponseEntity<HttpResponse> verifyPasswordUrl(@PathVariable("key") String key){
        UserDTO user = userService.verifyPasswordKey(key);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("user", user))
                .message("Please enter a new password")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build()
        );
    }
    @PostMapping("/resetpassword/{key}/{password}/{confirmpassword}")
    public ResponseEntity<HttpResponse> resetPasswordWithUrl(@PathVariable("key") String key, @PathVariable("password") String password, @PathVariable("confirmPassword") String confirmPassowrd){
        userService.renewPassword(key, password, confirmPassowrd);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .message("Password reset successfully")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build()
        );
    }
    @GetMapping("/verify/account/{key}")
    public ResponseEntity<HttpResponse> verifyAccount(@PathVariable("key") String key){
        UserDTO userDTO = userService.verifyAccount(key);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .message(userDTO.isEnabled() ? "Account already verified" : "Account verified")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build()
        );
    }

    public ResponseEntity<HttpResponse> refreshToken(HttpServletRequest request){
        if(isHeaderAndTokenValid(request)){
            String token = request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length());
            UserDTO userDTO = userService.getUserByEmail(tokenProvider.getSubject(token, request));
            return ResponseEntity.ok().body(
                    HttpResponse.builder()
                    .timeStamp(LocalDateTime.now().toString())
                    .data(Map.of("user", userDTO, "access_token", tokenProvider.createAccessToken(getUserPrincipal(userDTO)),
                            "refresh_token", token))
                    .message("Token refreshed")
                    .status(HttpStatus.OK)
                    .statusCode(HttpStatus.OK.value())
                    .build()
            );
        }else {
            return ResponseEntity.ok().body(
                    HttpResponse.builder()
                    .timeStamp(LocalDateTime.now().toString())
                    .reason("Refresh Token missing or invalid")
                    .status(HttpStatus.BAD_REQUEST)
                    .statusCode(HttpStatus.BAD_REQUEST.value())
                    .build()
            );
        }
    }

    @RequestMapping("/error")
    public ResponseEntity<HttpResponse> handleError(HttpServletRequest request){
        return ResponseEntity.badRequest().body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .reason("An error occurred " + request.getMethod())
                .status(HttpStatus.NOT_FOUND)
                .statusCode(HttpStatus.NOT_FOUND.value())
                .build()
        );
    }

    private boolean isHeaderAndTokenValid(HttpServletRequest request){
        return (request.getHeader(AUTHORIZATION) != null) &&
                (request.getHeader(AUTHORIZATION).startsWith(TOKEN_PREFIX)) &&
                (tokenProvider.isTokenValid(tokenProvider.getSubject(request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length()), request),
                        request.getHeader(AUTHORIZATION).substring(TOKEN_PREFIX.length())));
    }

    private UserDTO getAuthenticatedUser(Authentication authentication){
        return ((UserPrincipal) authentication.getPrincipal()).getUser();
    }

    private Authentication authenticate(String email, String password){
        try{
            Authentication authentication = authenticationManager.authenticate(unauthenticated(email, password));
            return authentication;
        }catch (Exception exception){
            processError(request, response, exception);
            throw new ApiException(exception.getMessage());
        }
    }

    private URI getUri(Long id){
        return URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/user/get/" + id).toUriString());
    }

    private ResponseEntity<HttpResponse> sendVerificationCode(UserDTO userDTO){
        this.userService.sendVerificationCode(userDTO);
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("user", userDTO))
                .message("Verification code sent")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build()
        );
    }

    private ResponseEntity<HttpResponse> sendResponse(UserDTO userDTO){
        return ResponseEntity.ok().body(
                HttpResponse.builder()
                .timeStamp(LocalDateTime.now().toString())
                .data(Map.of("user", userDTO,
                        "access_token", tokenProvider.createAccessToken(getUserPrincipal(userDTO)),
                        "refresh_token", tokenProvider.createRefreshToken(getUserPrincipal(userDTO))))
                .message("Login Success")
                .status(HttpStatus.OK)
                .statusCode(HttpStatus.OK.value())
                .build()
        );
    }

    private UserPrincipal getUserPrincipal(UserDTO userDTO){
        return new UserPrincipal(UserDTOMapper.toUser(this.userService.getUserByEmail(userDTO.getEmail())), this.roleService.getRoleByUserId(userDTO.getId()));
    }

}
