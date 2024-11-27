package com.example.kuby.todolist;

import com.example.kuby.KubyApplication;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.security.models.request.LoginRequest;
import com.example.kuby.test.utils.DbUtils;
import com.example.kuby.test.utils.JsonPrettyPrinter;
import com.example.kuby.test.utils.JwtPayloadParser;
import com.example.kuby.test.utils.TestContainersInitializer;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.UUID;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@Import({DbUtils.class, JwtPayloadParser.class})
@SpringBootTest(classes = {KubyApplication.class})
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class TaskControllerTest extends TestContainersInitializer {
    @Autowired
    private MockMvc mvc;
    @Autowired
    private JwtPayloadParser jwtPayloadParser;

    @Autowired
    private TaskRepo taskRepo;
    private static String authHeader;
    private static UUID taskId;
    @Autowired
    private DbUtils dbUtils;
    private final ObjectMapper objectMapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    @Order(1)
    public void init() throws Exception {
        UserEntity user = dbUtils.createUser();

        LoginRequest loginRequest = new LoginRequest(user.getEmail(), "18-Bad-Boy-18");

        mvc.perform(post("/api/user/login")
                        .characterEncoding(StandardCharsets.UTF_8)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(var1 -> {
                    System.out.println(var1.getResponse().getHeader("Authorization"));
                    authHeader = var1.getResponse().getHeader("Authorization");
                });
    }

    @Test
    @Order(2)
    public void create_success_test() throws Exception {
        CreateTaskRequest request = new CreateTaskRequest(
                "some name",
                LocalDateTime.now().plusMinutes(1),
                true
        );

        mvc.perform(post("/api/task")
                        .characterEncoding(StandardCharsets.UTF_8)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", authHeader)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(result -> JsonPrettyPrinter.print(result.getResponse().getContentAsString()));
        taskId = taskRepo.findAllByCreatorId(jwtPayloadParser.parseUserIdFromAuthHeader(authHeader)).get(0).getId();
    }

    @Test
    @Order(3)
    public void update_success_test() throws Exception {
        CreateTaskRequest request = new CreateTaskRequest();
        request.setDeadLine(LocalDateTime.now().plusYears(10));

        mvc.perform(put("/api/task/" + taskId.toString())
                        .characterEncoding(StandardCharsets.UTF_8)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", authHeader)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(result -> JsonPrettyPrinter.print(result.getResponse().getContentAsString()));
    }

    @Test
    @Order(4)
    public void delete_success_test() throws Exception {
        mvc.perform(delete("/api/task/" + taskId.toString())
                        .characterEncoding(StandardCharsets.UTF_8)
                        .contentType(MediaType.APPLICATION_JSON)
                        .header("Authorization", authHeader))
                .andExpect(status().isNoContent());
    }

    @Test
    @Order(5)
    public void getAll_success_test() throws Exception {
        LocalDateTime expiredDeadline = LocalDateTime.now().plusSeconds(5);

        for (int i = 0; i < 7; i++)
            taskRepo.save(Task.builder()
                    .name("soma name")
                    .deadLine(expiredDeadline)
                    .isFinished(false)
                    .creator(UserEntity.builder().id(jwtPayloadParser.parseUserIdFromAuthHeader(authHeader)).build())
                    .build());

        LocalDateTime nonExpiredDeadline = LocalDateTime.now().plusYears(1);

        for (int i = 0; i < 3; i++)
            taskRepo.save(Task.builder()
                    .name("soma name")
                    .deadLine(nonExpiredDeadline)
                    .isFinished(false)
                    .creator(UserEntity.builder().id(jwtPayloadParser.parseUserIdFromAuthHeader(authHeader)).build())
                    .build());

        Thread.sleep(5000);

        mvc.perform(get("/api/task")
                        .header("Authorization", authHeader))
                .andExpect(status().isOk())
                .andExpect(result -> JsonPrettyPrinter.print(result.getResponse().getContentAsString()));
    }
}
