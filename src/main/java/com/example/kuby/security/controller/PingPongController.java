package com.example.kuby.security.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequestMapping("/testing")
@RestController
public class PingPongController {

    @PostMapping
    public ResponseEntity<Void> testing(){

        return ResponseEntity.noContent().build();
    }
}
