package dev.iratherfear.springsecurity;

import java.util.ArrayList;
import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

record Todo(String username, String description) {}

@RestController
public class Controller {
    
    List<Todo> todos = new ArrayList<>(List.of(
        new Todo("user1", "Description 1"),
        new Todo("user2", "Description 2")
    ));

    @GetMapping("/")
    public String helloWorldMapping() {
        return new String("Hello World!!");
    }
    
    @GetMapping("/users/todos")
    public List<Todo> getMethodName() {
        return todos;
    }

    @PostMapping("/users/todos")
    public void createTodo( @RequestBody Todo todo) {
        todos.add(todo);
    }
}
