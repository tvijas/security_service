package com.example.kuby.security.controllers;

import com.example.kuby.KubyApplication;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.foruser.UserRepo;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.security.models.request.ChangePasswordRequest;
import com.example.kuby.security.models.request.LoginRequest;
import com.example.kuby.security.models.request.SignUpRequest;
import com.example.kuby.security.util.generate.CodeGenerator;
import com.example.kuby.test.utils.TestContainersInitializer;
import lombok.RequiredArgsConstructor;
import org.junit.jupiter.api.*;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.shaded.com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.head;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(classes = {KubyApplication.class}, properties = {"spring.profiles.active=test"})
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class UserAuthControllerTest extends TestContainersInitializer{

    @Value("${spring.mail.username}")
    private String email;
    @Autowired
    private UserRepo userRepo;
    @MockBean
    private CodeGenerator codeGenerator;
    @Autowired
    private PasswordEncoder encoder;
    private static String authHeader;
    @Autowired
    private MockMvc mvc;
    private final ObjectMapper objMapper = new ObjectMapper();

    @Test
    @Order(1)
    void test_register_verify_login() throws Exception {
        Mockito.when(this.codeGenerator.generateCode()).thenReturn("STRING_PIZDATIY_CODE");
        SignUpRequest signUpRequest = new SignUpRequest(email, "fsfsDSF@545AADFDGEWE3AR");

        mvc.perform(post("/api/user/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isCreated());

        mvc.perform(post("/api/user/verify/local")
                        .param("code", "STRING_PIZDATIY_CODE")
                        .param("email", email))
                .andExpect(status().isOk());

        LoginRequest loginRequest = new LoginRequest(email, "fsfsDSF@545AADFDGEWE3AR");

        mvc.perform(post("/api/user/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(header().exists("Authorization"))
                .andExpect(header().exists("X-Refresh-Token"))
                .andExpect(var1 -> authHeader = var1.getResponse().getHeader("Authorization"))
                .andDo(print());
    }

    @Order(2)
    @RepeatedTest(5)
    void test_secured_endpoint_success() throws Exception {
        mvc.perform(post("/testing")
                        .header("Authorization", authHeader))
                .andExpect(status().isNoContent());
    }

    @Test
    @Order(3)
    void test_wrong_domain_failure() throws Exception {
        SignUpRequest signUpRequest = new SignUpRequest("progamer2015@fimoz.club", "fsfsDSF@545AADFDGEWE3AR");
        mvc.perform(post("/api/user/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors['email']").value("Email doesn't exists"))
                .andDo(print());
    }

    @Test
    @Order(4)
    void test_password_change_success() throws Exception {
        Mockito.when(this.codeGenerator.generateCode()).thenReturn("STRING_PIZDATIY_CODE");
        ChangePasswordRequest changePasswordRequest = new ChangePasswordRequest(email, "123FimozikZ1GH4AIL41@34");

        mvc.perform(post("/api/user/change-password")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objMapper.writeValueAsString(changePasswordRequest)))
                .andExpect(status().isAccepted());

        mvc.perform(post("/api/user/summit-password-change")
                        .param("code", "STRING_PIZDATIY_CODE")
                        .param("email", email))
                .andExpect(status().isOk())
                .andExpect(var1 -> {
                    UserEntity user = userRepo.findByEmailAndProvider(email, Provider.LOCAL).get();
                    encoder.encode(user.getPassword()).equals("123FimozikZ1GH4AIL###41@34");
                });
    }
}
