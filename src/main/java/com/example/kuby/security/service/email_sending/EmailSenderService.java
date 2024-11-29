package com.example.kuby.security.service.email_sending;

import com.example.kuby.exceptions.BasicException;
import com.example.kuby.security.models.enums.Provider;
import com.example.kuby.foruser.UserRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;


@Service
@RequiredArgsConstructor
public class EmailSenderService {
    private final JavaMailSender javaMailSender;
    @Value("${spring.mail.username}")
    private String emailAdmin;
    @Value("${frontend.url}")
    private String frontEndUrl;
    @Value("${server.base-url}")
    private String backendUrl;


    @Transactional
    public void sendSubmissionLink(String toEmail, String code, String base) {

        String submissionUrl = frontEndUrl + "/user/" + base + "?code=" + code + "&email=" + toEmail;

        SimpleMailMessage simpleMailMessage = new SimpleMailMessage();
        simpleMailMessage.setFrom(emailAdmin);
        simpleMailMessage.setTo(toEmail);
        simpleMailMessage.setSubject("Email verification");
        simpleMailMessage.setText("To verify your action forward next link: \n\n" + submissionUrl);
        try {
            javaMailSender.send(simpleMailMessage);
        } catch (MailException ex) {
            throw new BasicException(Map.of("email", "Error occurred during email sending"), HttpStatus.BAD_REQUEST);
        }
    }
}
