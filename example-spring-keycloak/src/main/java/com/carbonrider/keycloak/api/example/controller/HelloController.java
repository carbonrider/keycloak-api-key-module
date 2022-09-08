package com.carbonrider.keycloak.api.example.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping(path = {"/hello"})
    public HelloMessage sayHello() {

        HelloMessage message = new HelloMessage();
        message.setMessage("hello there.");
        return message;
    }
}
