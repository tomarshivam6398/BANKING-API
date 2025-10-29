package com.example;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import jakarta.persistence.*;
import org.springframework.stereotype.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.*;
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.security.crypto.password.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.context.annotation.Configuration;
import org.springframework.beans.factory.annotation.Value;

import java.math.BigDecimal;
import java.util.*;
import java.util.stream.Collectors;
import java.io.IOException;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.filter.OncePerRequestFilter;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import java.security.Key;

// -----------------------------------------
// MAIN CLASS
// -----------------------------------------
@SpringBootApplication
public class BankingJWTApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankingJWTApplication.class, args);
    }

    // Seed sample user + accounts
    @Bean
    CommandLineRunner init(UserRepository userRepo, BankAccountRepository accRepo, PasswordEncoder encoder) {
        return args -> {
            if (!userRepo.existsByUsername("shivam")) {
                User u = new User();
                u.setUsername("shivam");
                u.setPassword(encoder.encode("pass123"));
                u.setRoles(Set.of("ROLE_USER"));
                userRepo.save(u);

                BankAccount a1 = new BankAccount("ACC1001", u, new BigDecimal("10000.00"));
                BankAccount a2 = new BankAccount("ACC2002", u, new BigDecimal("500.00"));
                accRepo.saveAll(List.of(a1, a2));
            }
        };
    }
}

// -----------------------------------------
// ENTITY: User
// -----------------------------------------
@Entity
@Table(name = "users")
class User {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String username;

    @Column(nullable = false)
    private String password;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "role")
    private Set<String> roles = new HashSet<>();

    public Long getId() { return id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public Set<String> getRoles() { return roles; }
    public void setRoles(Set<String> roles) { this.roles = roles; }
}

// -----------------------------------------
// ENTITY: BankAccount
// -----------------------------------------
@Entity
@Table(name = "accounts")
class BankAccount {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String accountNumber;

    @ManyToOne
    @JoinColumn(name = "user_id")
    private User owner;

    @Column(nullable = false)
    private BigDecimal balance = BigDecimal.ZERO;

    public BankAccount() {}
    public BankAccount(String accountNumber, User owner, BigDecimal balance) {
        this.accountNumber = accountNumber; this.owner = owner; this.balance = balance;
    }

    public Long getId() { return id; }
    public String getAccountNumber() { return accountNumber; }
    public void setAccountNumber(String acc) { this.accountNumber = acc; }
    public User getOwner() { return owner; }
    public void setOwner(User u) { this.owner = u; }
    public BigDecimal getBalance() { return balance; }
    public void setBalance(BigDecimal b) { this.balance = b; }
}

// -----------------------------------------
// REPOSITORIES
// -----------------------------------------
interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);
    boolean existsByUsername(String username);
}

interface BankAccountRepository extends JpaRepository<BankAccount, Long> {
    Optional<BankAccount> findByAccountNumber(String acc);
}

// -----------------------------------------
// SECURITY: JWT Utility
// -----------------------------------------
@Component
class JwtUtil {
    private final Key key;
    private final long expirationMs;

    public JwtUtil(@Value("${jwt.secret:default_secret_please_change}") String secret,
                   @Value("${jwt.expiration-ms:3600000}") long expirationMs) {
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.expirationMs = expirationMs;
    }

    public String generateToken(String username, Set<String> roles) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);
        return Jwts.builder()
                .setSubject(username)
                .claim("roles", roles)
                .setIssuedAt(now)
                .setExpiration(expiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try { Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token); return true; }
        catch (JwtException e) { return false; }
    }

    public String getUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().getSubject();
    }

    @SuppressWarnings("unchecked")
    public Set<String> getRoles(String token) {
        Object roles = Jwts.parserBuilder().setSigningKey(key).build()
                .parseClaimsJws(token).getBody().get("roles");
        if (roles instanceof Collection<?>) {
            return ((Collection<?>) roles).stream().map(Object::toString).collect(Collectors.toSet());
        }
        return Collections.emptySet();
    }
}

// -----------------------------------------
// SECURITY: Custom UserDetailsService
// -----------------------------------------
@Service
class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository repo;
    public CustomUserDetailsService(UserRepository repo) { this.repo = repo; }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User u = repo.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return org.springframework.security.core.userdetails.User.builder()
                .username(u.getUsername())
                .password(u.getPassword())
                .authorities(u.getRoles().stream().map(SimpleGrantedAuthority::new).toList())
                .build();
    }
}

// -----------------------------------------
// SECURITY: JWT Filter
// -----------------------------------------
@Component
class JwtFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;
    private final CustomUserDetailsService userDetailsService;

    public JwtFilter(JwtUtil jwtUtil, CustomUserDetailsService userDetailsService) {
        this.jwtUtil = jwtUtil; this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest req,
                                    jakarta.servlet.http.HttpServletResponse res,
                                    jakarta.servlet.FilterChain chain)
            throws IOException, jakarta.servlet.ServletException {

        final String authHeader = req.getHeader("Authorization");
        String token = null, username = null;

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            if (jwtUtil.validateToken(token)) username = jwtUtil.getUsername(token);
        }

        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails ud = userDetailsService.loadUserByUsername(username);
            if (jwtUtil.validateToken(token)) {
                Set<String> roles = jwtUtil.getRoles(token);
                var authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new).collect(Collectors.toList());
                UsernamePasswordAuthenticationToken auth =
                        new UsernamePasswordAuthenticationToken(ud, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        chain.doFilter(req, res);
    }
}

// -----------------------------------------
// SECURITY CONFIG
// -----------------------------------------
@Configuration
@EnableMethodSecurity
class SecurityConfig {
    private final JwtFilter jwtFilter;
    private final CustomUserDetailsService userDetailsService;

    public SecurityConfig(JwtFilter jwtFilter, CustomUserDetailsService uds) {
        this.jwtFilter = jwtFilter; this.userDetailsService = uds;
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    .requestMatchers("/auth/**", "/h2-console/**").permitAll()
                    .anyRequest().authenticated()
            );
        http.headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));
        http.addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    @Bean PasswordEncoder passwordEncoder() { return new BCryptPasswordEncoder(); }

    @Bean AuthenticationManager authManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }
}

// -----------------------------------------
// CONTROLLER: AUTH
// -----------------------------------------
@RestController
@RequestMapping("/auth")
class AuthController {
    private final UserRepository userRepo;
    private final PasswordEncoder encoder;
    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    public AuthController(UserRepository repo, PasswordEncoder encoder,
                          AuthenticationManager authManager, JwtUtil jwtUtil) {
        this.userRepo = repo; this.encoder = encoder;
        this.authManager = authManager; this.jwtUtil = jwtUtil;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String,String> body) {
        String username = body.get("username");
        String password = body.get("password");
        if (userRepo.existsByUsername(username))
            return ResponseEntity.badRequest().body("Username already exists");
        User u = new User();
        u.setUsername(username);
        u.setPassword(encoder.encode(password));
        u.setRoles(Set.of("ROLE_USER"));
        userRepo.save(u);
        return ResponseEntity.ok("User registered");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String,String> body) {
        try {
            authManager.authenticate(
                new UsernamePasswordAuthenticationToken(body.get("username"), body.get("password")));
            User u = userRepo.findByUsername(body.get("username")).orElseThrow();
            String token = jwtUtil.generateToken(u.getUsername(), u.getRoles());
            return ResponseEntity.ok(Map.of("token", token));
        } catch (BadCredentialsException ex) {
            return ResponseEntity.status(401).body("Invalid credentials");
        }
    }
}

// -----------------------------------------
// CONTROLLER: BANK
// -----------------------------------------
@RestController
@RequestMapping("/api/accounts")
class BankController {
    private final BankAccountRepository accRepo;
    private final UserRepository userRepo;

    public BankController(BankAccountRepository accRepo, UserRepository userRepo) {
        this.accRepo = accRepo; this.userRepo = userRepo;
    }

    @GetMapping("/my")
    public ResponseEntity<?> myAccounts(@AuthenticationPrincipal UserDetails ud) {
        User u = userRepo.findByUsername(ud.getUsername()).orElseThrow();
        var accounts = accRepo.findAll().stream()
                .filter(a -> a.getOwner().getId().equals(u.getId()))
                .toList();
        return ResponseEntity.ok(accounts);
    }

    @PostMapping("/transfer")
    @Transactional
    public ResponseEntity<?> transfer(@AuthenticationPrincipal UserDetails ud,
                                      @RequestBody Map<String,String> body) {
        String fromAcc = body.get("fromAccount");
        String toAcc = body.get("toAccount");
        BigDecimal amount = new BigDecimal(body.get("amount"));
        BankAccount from = accRepo.findByAccountNumber(fromAcc)
                .orElseThrow(() -> new RuntimeException("From account not found"));
        BankAccount to = accRepo.findByAccountNumber(toAcc)
                .orElseThrow(() -> new RuntimeException("To account not found"));
        User u = userRepo.findByUsername(ud.getUsername()).orElseThrow();
        if (!from.getOwner().getId().equals(u.getId()))
            return ResponseEntity.status(403).body("Unauthorized access to account");
        if (from.getBalance().compareTo(amount) < 0)
            return ResponseEntity.badRequest().body("Insufficient funds");

        from.setBalance(from.getBalance().subtract(amount));
        to.setBalance(to.getBalance().add(amount));
        accRepo.save(from); accRepo.save(to);
        return ResponseEntity.ok(Map.of("status", "success"));
    }
}
