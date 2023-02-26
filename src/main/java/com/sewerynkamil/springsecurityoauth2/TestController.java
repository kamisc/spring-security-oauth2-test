package com.sewerynkamil.springsecurityoauth2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {
    @GetMapping("/for-all")
    public String getForAll() {
        return "Hello you!";
    }

    @GetMapping("/for-user")
    public String getForUser() {
        return "Hello User!";
    }

    @GetMapping("/for-admin")
    public String getForAdmin() {
        return "Hello Admin!";
    }
}
