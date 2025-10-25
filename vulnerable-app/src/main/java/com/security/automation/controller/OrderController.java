package com.security.automation.controller;

import com.security.automation.model.Order;
import com.security.automation.repository.OrderRepository;
import com.security.automation.security.AuthorizationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/companies")
public class OrderController {

  @Autowired
  private OrderRepository orderRepository;

  @Autowired
  private AuthorizationService authorizationService;

  /**
   * VULNERABILITY 3: Complex IDOR/Logic Flaw
   * The @PreAuthorize checks if the user owns the order, but does NOT validate
   * that the order belongs to the specified company in the URL path.
   * 
   * Attack scenario:
   * - Alice owns Company A, Order 1
   * - Bob owns Company B, Order 2
   * - Alice can access /api/companies/B/orders/1 even though Order 1 doesn't
   * belong to Company B
   * - The isOrderOwner check only verifies Alice owns Order 1, not the company
   * context
   */
  @GetMapping("/{companyId}/orders/{orderId}")
  @PreAuthorize("@authorizationService.isOrderOwner(#orderId)")
  public ResponseEntity<?> getOrder(
      @PathVariable Long companyId,
      @PathVariable Long orderId) {

    Order order = orderRepository.findById(orderId).orElse(null);
    if (order == null) {
      return ResponseEntity.notFound().build();
    }

    // BUG: Should validate that order.getCompany().getId().equals(companyId)
    // Currently only validates order ownership via @PreAuthorize
    return ResponseEntity.ok(order);
  }

  /**
   * Update shipping address - also vulnerable to the same complex IDOR
   */
  @PutMapping("/{companyId}/orders/{orderId}/shipping")
  @PreAuthorize("@authorizationService.isOrderOwner(#orderId)")
  public ResponseEntity<?> updateShippingAddress(
      @PathVariable Long companyId,
      @PathVariable Long orderId,
      @RequestBody String newAddress) {

    Order order = orderRepository.findById(orderId).orElse(null);
    if (order == null) {
      return ResponseEntity.notFound().build();
    }

    // BUG: Missing company context validation
    order.setShippingAddress(newAddress);
    orderRepository.save(order);

    return ResponseEntity.ok(order);
  }

  /**
   * List all orders for a company (simplified for testing)
   */
  @GetMapping("/{companyId}/orders")
  public ResponseEntity<?> listOrders(@PathVariable Long companyId) {
    List<Order> orders = orderRepository.findByCompanyId(companyId);
    return ResponseEntity.ok(orders);
  }
}
