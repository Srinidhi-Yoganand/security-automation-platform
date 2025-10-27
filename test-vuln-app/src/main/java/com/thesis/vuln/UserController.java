package com.thesis.vuln;

import org.springframework.web.bind.annotation.*;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * VULNERABLE: IDOR - User ID from path variable flows directly to findById
 * without authorization check
 */
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    private final UserRepository userRepository;
    
    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }
    
    /**
     * IDOR Vulnerability: Any user can access any other user's data
     * by manipulating the userId path parameter
     */
    @GetMapping("/{userId}")
    public User getUserById(@PathVariable Long userId) {
        // VULNERABLE: No authorization check!
        // An attacker can change userId to access other users' data
        return userRepository.findById(userId).orElse(null);
    }
    
    /**
     * Another IDOR: User can access any order by changing orderId
     */
    @GetMapping("/{userId}/orders/{orderId}")
    public Order getUserOrder(
            @PathVariable Long userId,
            @PathVariable Long orderId) {
        // VULNERABLE: orderId flows directly to findById without checking
        // if the order belongs to the authenticated user
        OrderRepository orderRepo = null; // simplified
        return orderRepo.findById(orderId).orElse(null);
    }
    
    /**
     * SAFE Example: Proper authorization check
     */
    @GetMapping("/secure/{userId}")
    public User getUserByIdSecure(@PathVariable Long userId) {
        // Get authenticated user from security context
        Long authenticatedUserId = getCurrentAuthenticatedUserId();
        
        // Authorization check
        if (!userId.equals(authenticatedUserId)) {
            throw new SecurityException("Access denied");
        }
        
        return userRepository.findById(userId).orElse(null);
    }
    
    private Long getCurrentAuthenticatedUserId() {
        // Simplified - would use SecurityContextHolder in real app
        return 1L;
    }
}
