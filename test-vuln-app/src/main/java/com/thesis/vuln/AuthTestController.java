package com.thesis.vuln;

import org.springframework.web.bind.annotation.*;
import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Test cases for authorization detection queries
 * Mix of vulnerable and secure endpoints
 * 
 * Note: Authentication parameter is simplified - normally would use
 * Spring Security's SecurityContextHolder
 */
@RestController
@RequestMapping("/api/test")
public class AuthTestController {
    
    private final UserRepository userRepository;
    private final OrderRepository orderRepository;
    
    public AuthTestController(UserRepository userRepository, OrderRepository orderRepository) {
        this.userRepository = userRepository;
        this.orderRepository = orderRepository;
    }
    
    // ========================================
    // VULNERABLE ENDPOINTS (Should be detected)
    // ========================================
    
    /**
     * VULN-1: Direct ID access without any authorization
     */
    @GetMapping("/users/{userId}")
    public User getUser(@PathVariable Long userId) {
        return userRepository.findById(userId).orElse(null);
    }
    
    /**
     * VULN-2: Query parameter without authorization
     */
    @GetMapping("/user-profile")
    public User getUserProfile(@RequestParam("id") Long userId) {
        return userRepository.findById(userId).orElse(null);
    }
    
    /**
     * VULN-3: Nested resource access without ownership check
     */
    @GetMapping("/users/{userId}/orders/{orderId}")
    public Order getUserOrder(
            @PathVariable Long userId,
            @PathVariable Long orderId) {
        // Vulnerable: orderId is used directly without checking if it belongs to userId
        return orderRepository.findById(orderId).orElse(null);
    }
    
    /**
     * VULN-4: Delete endpoint without authorization
     */
    @DeleteMapping("/users/{userId}")
    public void deleteUser(@PathVariable Long userId) {
        userRepository.deleteById(userId);
    }
    
    /**
     * VULN-5: Update without authorization
     */
    @PutMapping("/users/{userId}")
    public User updateUser(@PathVariable Long userId, @RequestBody User user) {
        User existing = userRepository.findById(userId).orElse(null);
        if (existing != null) {
            existing.setName(user.getName());
            return userRepository.save(existing);
        }
        return null;
    }
    
    // ========================================
    // SECURE ENDPOINTS (Should NOT be detected)
    // ========================================
    
    /**
     * SECURE-1: Proper ownership check
     */
    @GetMapping("/secure/users/{userId}")
    public User getUserSecure(@PathVariable Long userId, @RequestHeader("X-User-Id") String authUserId) {
        Long authenticatedUserId = Long.parseLong(authUserId);
        
        // Authorization check
        if (!userId.equals(authenticatedUserId)) {
            throw new SecurityException("Access denied");
        }
        
        return userRepository.findById(userId).orElse(null);
    }
    
    /**
     * SECURE-2: Using Spring Security PreAuthorize annotation (commented for compilation)
     */
    @GetMapping("/secure/admin/users/{userId}")
    // @PreAuthorize("hasRole('ADMIN')")  // Would need Spring Security dependency
    public User getUserAdmin(@PathVariable Long userId) {
        // In real app, this would be secured by annotation
        return userRepository.findById(userId).orElse(null);
    }
    
    /**
     * SECURE-3: Method-level permission check
     */
    @GetMapping("/secure/orders/{orderId}")
    public Order getOrderSecure(@PathVariable Long orderId, @RequestHeader("X-User-Id") String authUserId) {
        Order order = orderRepository.findById(orderId).orElse(null);
        
        if (order != null && !canAccessOrder(Long.parseLong(authUserId), order)) {
            throw new SecurityException("You don't have permission to access this order");
        }
        
        return order;
    }
    
    /**
     * SECURE-4: Only returns authenticated user's own data
     */
    @GetMapping("/secure/my-profile")
    public User getMyProfile(@RequestHeader("X-User-Id") String authUserId) {
        Long userId = Long.parseLong(authUserId);
        return userRepository.findById(userId).orElse(null);
    }
    
    // ========================================
    // Helper methods
    // ========================================
    
    private boolean canAccessOrder(Long userId, Order order) {
        return order.getUserId().equals(userId);
    }
}
