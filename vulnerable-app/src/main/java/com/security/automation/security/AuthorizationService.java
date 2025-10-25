package com.security.automation.security;

import com.security.automation.model.Order;
import com.security.automation.repository.OrderRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
public class AuthorizationService {

  @Autowired
  private OrderRepository orderRepository;

  /**
   * INTENTIONAL FLAW: This method only checks if the user is authenticated,
   * not if the userId matches the current user. This is a simple IDOR
   * vulnerability.
   */
  public boolean isMe(String userId) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    // BUG: Should compare userId with authentication.getName()
    return authentication != null && authentication.isAuthenticated();
  }

  /**
   * INTENTIONAL FLAW: This method checks if the user owns an order,
   * but it does NOT validate that the order belongs to the company specified in
   * the URL.
   * This is a complex multi-step IDOR vulnerability.
   */
  public boolean isOrderOwner(Long orderId) {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (authentication == null || !authentication.isAuthenticated()) {
      return false;
    }

    String username = authentication.getName();
    Order order = orderRepository.findById(orderId).orElse(null);

    if (order == null) {
      return false;
    }

    // BUG: Only checks order ownership, not company context
    // Should also verify: order.getCompany().getId() == companyId from URL
    return order.getUser().getUsername().equals(username);
  }

  /**
   * Helper method to check if the current user is an admin.
   */
  public boolean isAdmin() {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    return authentication != null &&
        authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN"));
  }
}
