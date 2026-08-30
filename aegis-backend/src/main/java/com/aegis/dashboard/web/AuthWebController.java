package com.aegis.dashboard.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AuthWebController {

    @GetMapping("/")
    public String root() {
        return "redirect:/web/dashboard";
    }

    @GetMapping("/login")
    public String login() {
        return "login";
    }
}
