package com.example.kuby.security.service.user;

import com.example.kuby.KubyApplication;
import com.example.kuby.foruser.CustomUserDetails;
import com.example.kuby.foruser.CustomUserPrincipal;
import com.example.kuby.foruser.UserCache;
import com.example.kuby.foruser.UserEntity;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.test.utils.DbUtils;
import com.example.kuby.test.utils.TestContainersInitializer;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Import(DbUtils.class)
@SpringBootTest(classes = {KubyApplication.class}, properties = {"spring.profiles.active=test"})
public class UsersServiceTests extends TestContainersInitializer {
    @Autowired
    UserService userService;
    @Autowired
    DbUtils dbUtils;
    @Test
    void loadUserByUsername(){
        UserEntity user = dbUtils.createUser();

        Optional<UserCache> userDetails = userService.loadUserByUsername(user.getPrincipal().email(), Provider.LOCAL);

        assertTrue(userDetails.isPresent());
    }
}
