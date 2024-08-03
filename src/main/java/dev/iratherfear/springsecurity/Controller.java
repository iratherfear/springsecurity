package dev.iratherfear.springsecurity;

import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;


@RestController
@RequiredArgsConstructor
public class Controller {
    
    @GetMapping("/")
    public String getHelloWorld() {
        return new String("Hello W11orld!!");
    }
    
}
