package com.security.automation.controller;

import com.security.automation.model.User;
import com.security.automation.repository.UserRepository;
import com.security.automation.security.AuthorizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private AuthorizationService authorizationService;

    /**
     * VULNERABILITY 1: SQL Injection
     * Simple SQLi vulnerability - directly concatenating user input into SQL query
     */
    @GetMapping("/search")
    public ResponseEntity<?> searchUsers(@RequestParam String username) {
        // VULNERABLE: SQL Injection
        String sql = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";
        List<Map<String, Object>> results = jdbcTemplate.queryForList(sql);
        return ResponseEntity.ok(results);
    }

    /**
     * VULNERABILITY 2: Simple IDOR
     * The @PreAuthorize annotation promises to check "isMe" but the implementation is flawed
     */
    @GetMapping("/{userId}")
    @PreAuthorize("@authorizationService.isMe(#userId)")
    public ResponseEntity<?> getUser(@PathVariable String userId) {
        User user = userRepository.findById(Long.parseLong(userId)).orElse(null);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(user);
    }

    /**
     * Admin-only endpoint for testing
     */
    @DeleteMapping("/{userId}")
    @PreAuthorize("@authorizationService.isAdmin()")
    public ResponseEntity<?> deleteUser(@PathVariable Long userId) {
        userRepository.deleteById(userId);
        return ResponseEntity.ok("User deleted");
    }

    /**
     * Public endpoint to list all users (intentionally insecure for testing)
     */
    @GetMapping("/public/all")
    public ResponseEntity<?> getAllUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }
}
