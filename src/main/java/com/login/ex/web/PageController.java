package com.login.ex.web;

import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class PageController {

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }

    @GetMapping("/home")
    public String homePage(Authentication auth, Model model) {
        model.addAttribute("username", auth != null ? auth.getName() : "anonymous");
        return "home";
    }
}
