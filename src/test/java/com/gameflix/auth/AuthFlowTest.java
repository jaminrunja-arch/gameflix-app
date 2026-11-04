package com.gameflix.auth;

import com.gameflix.auth.model.User;
import com.gameflix.auth.repository.UserRepository;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AuthFlowTest {

    private static final String EMAIL = "jamin@test.com";
    private static final String PASSWORD = "Password123!";

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Value("${jwt.issuer}")
    private String issuer;

    @BeforeEach
    void clearUsers() {
        userRepository.deleteAll();
    }

    @Test
    void registerReturns201AndNeverReturnsPassword() throws Exception {
        register("jamin", EMAIL, PASSWORD)
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").isNumber())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void passwordIsStoredAsBcryptHash() throws Exception {
        register("jamin", EMAIL, PASSWORD).andExpect(status().isCreated());

        User saved = userRepository.findByEmail(EMAIL).orElseThrow();
        assertThat(saved.getPassword()).isNotEqualTo(PASSWORD);
        assertThat(saved.getPassword()).startsWith("{bcrypt}$2a$12$");
        assertThat(saved.getPassword()).hasSize(68);
    }

    @Test
    void duplicateEmailReturns409() throws Exception {
        register("jamin", EMAIL, PASSWORD).andExpect(status().isCreated());

        register("someoneelse", EMAIL, "DifferentPass1!")
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.error").value("Email is already registered"));
    }

    @Test
    void invalidRegistrationReturns400() throws Exception {
        register("jamin", "not-an-email", "short")
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.fields.email").exists())
                .andExpect(jsonPath("$.fields.password").exists());
    }

    @Test
    void loginReturnsTokenWithExpClaim() throws Exception {
        register("jamin", EMAIL, PASSWORD).andExpect(status().isCreated());

        String body = login(EMAIL, PASSWORD)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isString())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn().getResponse().getContentAsString();

        String token = JsonPath.read(body, "$.token");
        String payload = new String(Base64.getUrlDecoder().decode(token.split("\\.")[1]), StandardCharsets.UTF_8);
        assertThat(payload).contains("\"exp\"");
        assertThat(payload).doesNotContain(PASSWORD);
        assertThat(payload).doesNotContain(EMAIL);
    }

    @Test
    void loginWithWrongPasswordReturns401() throws Exception {
        register("jamin", EMAIL, PASSWORD).andExpect(status().isCreated());

        login(EMAIL, "WrongPassword1!")
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid email or password"));
    }

    @Test
    void loginWithUnknownEmailGivesSameMessage() throws Exception {
        login("nobody@test.com", PASSWORD)
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.error").value("Invalid email or password"));
    }

    @Test
    void meWithValidTokenReturnsProfile() throws Exception {
        register("jamin", EMAIL, PASSWORD).andExpect(status().isCreated());
        String token = loginAndGetToken();

        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value(EMAIL))
                .andExpect(jsonPath("$.username").value("jamin"))
                .andExpect(jsonPath("$.password").doesNotExist());
    }

    @Test
    void meWithoutTokenReturns401() throws Exception {
        mockMvc.perform(get("/api/users/me"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void meWithTamperedTokenReturns401() throws Exception {
        register("jamin", EMAIL, PASSWORD).andExpect(status().isCreated());
        String token = loginAndGetToken();

        String[] parts = token.split("\\.");
        char[] signature = parts[2].toCharArray();
        signature[10] = signature[10] == 'A' ? 'B' : 'A';
        String tampered = parts[0] + "." + parts[1] + "." + new String(signature);

        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + tampered))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void meWithExpiredTokenReturns401() throws Exception {
        register("jamin", EMAIL, PASSWORD).andExpect(status().isCreated());
        Long id = userRepository.findByEmail(EMAIL).orElseThrow().getId();

        Instant twoHoursAgo = Instant.now().minusSeconds(7200);
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(twoHoursAgo)
                .expiresAt(twoHoursAgo.plusSeconds(1800))
                .subject(String.valueOf(id))
                .build();
        String expired = encode(claims);

        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void tokenWithoutExpIsRejected() throws Exception {
        register("jamin", EMAIL, PASSWORD).andExpect(status().isCreated());
        Long id = userRepository.findByEmail(EMAIL).orElseThrow().getId();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .issuedAt(Instant.now())
                .subject(String.valueOf(id))
                .build();
        String noExp = encode(claims);

        mockMvc.perform(get("/api/users/me").header("Authorization", "Bearer " + noExp))
                .andExpect(status().isUnauthorized());
    }

    private ResultActions register(String username, String email, String password) throws Exception {
        String json = """
                {"username": "%s", "email": "%s", "password": "%s"}
                """.formatted(username, email, password);
        return mockMvc.perform(post("/api/auth/register").contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private ResultActions login(String email, String password) throws Exception {
        String json = """
                {"email": "%s", "password": "%s"}
                """.formatted(email, password);
        return mockMvc.perform(post("/api/auth/login").contentType(MediaType.APPLICATION_JSON).content(json));
    }

    private String loginAndGetToken() throws Exception {
        String body = login(EMAIL, PASSWORD).andReturn().getResponse().getContentAsString();
        return JsonPath.read(body, "$.token");
    }

    private String encode(JwtClaimsSet claims) {
        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
