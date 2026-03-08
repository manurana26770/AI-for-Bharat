package com.varutri.honeypot.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.Components;
import org.springdoc.core.models.GroupedOpenApi;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI varutriOpenAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Varutri Honeypot API")
                        .description("""
                                **Varutri Agentic Honeypot System** — AI-powered scam intelligence platform.

                                This API provides endpoints for:
                                - **Chat**: Engage with scammers using AI personas to extract intelligence
                                - **Persona**: Manage honeypot AI personas at runtime
                                - **Reports**: Generate and retrieve scam intelligence reports
                                - **Health**: Monitor system status

                                ### How It Works
                                1. Scammer sends a message via `/api/chat`
                                2. AI persona responds naturally while extracting UPI IDs, bank accounts, phone numbers, and URLs
                                3. Threat assessment runs via 5-layer ensemble scoring
                                4. Intelligence is collected and reports are generated automatically

                                ### Authentication
                                All API endpoints require an `X-API-Key` header for authentication.
                                """)
                        .version("1.0.0")
                        .contact(new Contact()
                                .name("Varutri Team")
                                .email("team@varutri.com"))
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT")))
                .servers(List.of(
                        new Server().url("/").description("Current Server")))
                .addSecurityItem(new SecurityRequirement().addList("ApiKeyAuth"))
                .components(new Components()
                        .addSecuritySchemes("ApiKeyAuth", new SecurityScheme()
                                .type(SecurityScheme.Type.APIKEY)
                                .in(SecurityScheme.In.HEADER)
                                .name("X-API-Key")
                                .description("API Key for authentication. Pass in the X-API-Key header.")));
    }

    @Bean
    public GroupedOpenApi publicApi() {
        return GroupedOpenApi.builder()
                .group("varutri-honeypot")
                .pathsToMatch("/api/health", "/api/chat", "/api/assess",
                        "/api/callback/**", "/api/evidence/**",
                        "/api/persona/**", "/api/report/**")
                .pathsToExclude("/api/whatsapp/**", "/api/test/**")
                .build();
    }
}
