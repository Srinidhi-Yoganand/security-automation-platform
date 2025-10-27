package com.thesis.vuln;

import org.springframework.data.jpa.repository.JpaRepository;

/**
 * Shared domain models and repositories for test cases
 */

// User entity
class User {
    private Long id;
    private String name;
    private String email;
    private String ssn;
    
    public Long getId() { return id; }
    public String getName() { return name; }
    public String getEmail() { return email; }
    public void setId(Long id) { this.id = id; }
    public void setName(String name) { this.name = name; }
    public void setEmail(String email) { this.email = email; }
}

// Order entity
class Order {
    private Long id;
    private Long userId;
    private Double total;
    
    public Long getId() { return id; }
    public Long getUserId() { return userId; }
    public Double getTotal() { return total; }
    public void setId(Long id) { this.id = id; }
    public void setUserId(Long userId) { this.userId = userId; }
    public void setTotal(Double total) { this.total = total; }
}

// Repositories
interface UserRepository extends JpaRepository<User, Long> {
}

interface OrderRepository extends JpaRepository<Order, Long> {
}
