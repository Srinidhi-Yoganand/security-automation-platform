package com.security.automation.service;

import com.security.automation.model.Company;
import com.security.automation.model.Order;
import com.security.automation.model.User;
import com.security.automation.repository.CompanyRepository;
import com.security.automation.repository.OrderRepository;
import com.security.automation.repository.UserRepository;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Arrays;

@Service
public class DataInitializationService {

  @Autowired
  private UserRepository userRepository;

  @Autowired
  private CompanyRepository companyRepository;

  @Autowired
  private OrderRepository orderRepository;

  @Autowired
  private PasswordEncoder passwordEncoder;

  @PostConstruct
  public void initializeData() {
    // Create users
    User alice = new User();
    alice.setUsername("alice");
    alice.setPassword(passwordEncoder.encode("alice123"));
    alice.setEmail("alice@example.com");
    alice.setSsn("111-11-1111");
    alice.setRole("USER");
    alice.setAddress("123 Main St");
    alice = userRepository.save(alice);

    User bob = new User();
    bob.setUsername("bob");
    bob.setPassword(passwordEncoder.encode("bob123"));
    bob.setEmail("bob@example.com");
    bob.setSsn("222-22-2222");
    bob.setRole("USER");
    bob.setAddress("456 Oak Ave");
    bob = userRepository.save(bob);

    User admin = new User();
    admin.setUsername("admin");
    admin.setPassword(passwordEncoder.encode("admin123"));
    admin.setEmail("admin@example.com");
    admin.setSsn("999-99-9999");
    admin.setRole("ADMIN");
    admin.setAddress("789 Admin Blvd");
    admin = userRepository.save(admin);

    // Create companies
    Company acmeCorp = new Company();
    acmeCorp.setName("ACME Corp");
    acmeCorp.setAddress("100 Business Plaza");
    acmeCorp.setOwner(alice);
    acmeCorp = companyRepository.save(acmeCorp);

    Company techCo = new Company();
    techCo.setName("TechCo Industries");
    techCo.setAddress("200 Innovation Drive");
    techCo.setOwner(bob);
    techCo = companyRepository.save(techCo);

    // Create orders
    Order order1 = new Order();
    order1.setUser(alice);
    order1.setCompany(acmeCorp);
    order1.setProductName("Laptop");
    order1.setAmount(new BigDecimal("1200.00"));
    order1.setShippingAddress(alice.getAddress());
    order1.setStatus("PENDING");
    order1.setCreatedAt(LocalDateTime.now());
    orderRepository.save(order1);

    Order order2 = new Order();
    order2.setUser(bob);
    order2.setCompany(techCo);
    order2.setProductName("Monitor");
    order2.setAmount(new BigDecimal("300.00"));
    order2.setShippingAddress(bob.getAddress());
    order2.setStatus("SHIPPED");
    order2.setCreatedAt(LocalDateTime.now());
    orderRepository.save(order2);

    Order order3 = new Order();
    order3.setUser(alice);
    order3.setCompany(acmeCorp);
    order3.setProductName("Keyboard");
    order3.setAmount(new BigDecimal("80.00"));
    order3.setShippingAddress(alice.getAddress());
    order3.setStatus("DELIVERED");
    order3.setCreatedAt(LocalDateTime.now());
    orderRepository.save(order3);

    System.out.println("=== Test Data Initialized ===");
    System.out.println("Users: alice (USER), bob (USER), admin (ADMIN)");
    System.out.println("Companies: ACME Corp (alice), TechCo (bob)");
    System.out.println("Orders: 3 orders created");
  }
}
