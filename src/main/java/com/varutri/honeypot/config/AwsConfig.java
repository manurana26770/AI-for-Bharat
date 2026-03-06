package com.varutri.honeypot.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.enhanced.dynamodb.DynamoDbEnhancedClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.bedrockruntime.BedrockRuntimeClient;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;

/**
 * AWS configuration for Bedrock and DynamoDB clients.
 * Uses the default AWS credential provider chain (env vars / IAM role /
 * profile).
 */
@Configuration
public class AwsConfig {

        @Value("${AWS_ACCESS_KEY_ID:}")
        private String accessKeyId;

        @Value("${AWS_SECRET_ACCESS_KEY:}")
        private String secretAccessKey;

        /**
         * Bedrock Runtime client — only created when llm.provider=bedrock.
         */
        @Bean
        @ConditionalOnProperty(name = "llm.provider", havingValue = "bedrock")
        public BedrockRuntimeClient bedrockRuntimeClient(
                        @Value("${aws.bedrock.region:us-east-1}") String region) {
                return BedrockRuntimeClient.builder()
                                .region(Region.of(region))
                                .credentialsProvider(getStaticCredentialsProvider())
                                .build();
        }

        /**
         * DynamoDB Enhanced Client — always created (data layer).
         */
        @Bean
        public DynamoDbEnhancedClient dynamoDbEnhancedClient(
                        @Value("${aws.dynamodb.region:us-east-1}") String region) {
                DynamoDbClient ddbClient = DynamoDbClient.builder()
                                .region(Region.of(region))
                                .credentialsProvider(getStaticCredentialsProvider())
                                .build();
                return DynamoDbEnhancedClient.builder()
                                .dynamoDbClient(ddbClient)
                                .build();
        }

        private StaticCredentialsProvider getStaticCredentialsProvider() {
                if (accessKeyId == null || accessKeyId.isEmpty() || secretAccessKey == null
                                || secretAccessKey.isEmpty()) {
                        throw new IllegalStateException("AWS credentials are missing. Please check your .env file.");
                }
                return StaticCredentialsProvider.create(
                                AwsBasicCredentials.create(accessKeyId, secretAccessKey));
        }
}
