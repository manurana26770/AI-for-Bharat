package com.varutri.honeypot.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * PersonaProfile represents the identity of the honeypot AI persona.
 * This profile is used to dynamically generate system prompts for the LLM.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PersonaProfile {

    private String name;
    private int age;
    private String profession;
    private String city;
    private String country;
    private String livingStatus;
    private String techLevel;

    private List<String> personalityTraits;
    private List<String> languageStyle;
    private List<String> commonMistakes;
    private List<String> examplePhrases;

    /**
     * Generates a system prompt string from the persona profile fields.
     * This prompt is used to instruct the LLM on how to behave.
     */
    public String toSystemPrompt() {
        StringBuilder prompt = new StringBuilder();

        // Basic identity
        // Dynamic Identity Instruction
        prompt.append("CORE INSTRUCTION: You are a dynamic honeypot agent designed to waste scammers' time.\n");
        prompt.append(
                "1. ADAPTABILITY: If the user addresses you by a specific name, age, or profession, ADOPT THAT IDENTITY immediately. Do not correct them.\n");
        prompt.append("2. FALLBACK IDENTITY: If no identity is implied by the user, you are ").append(name)
                .append(", a ").append(age).append("-year-old ").append(profession).append(" from ")
                .append(city).append(", ").append(country).append(".\n");
        prompt.append(livingStatus).append(" ").append(techLevel).append("\n\n");

        // Personality traits
        if (personalityTraits != null && !personalityTraits.isEmpty()) {
            prompt.append("PERSONALITY:\n");
            for (String trait : personalityTraits) {
                prompt.append("- ").append(trait).append("\n");
            }
            prompt.append("\n");
        }

        // Language style instructions
        if (languageStyle != null && !languageStyle.isEmpty()) {
            prompt.append("LANGUAGE STYLE (VERY IMPORTANT):\n");
            for (String style : languageStyle) {
                prompt.append("- ").append(style).append("\n");
            }
            prompt.append("\n");
        }

        // Example phrases
        if (examplePhrases != null && !examplePhrases.isEmpty()) {
            prompt.append("EXAMPLES OF YOUR STYLE:\n");
            for (String example : examplePhrases) {
                prompt.append("- \"").append(example).append("\"\n");
            }
            prompt.append("\n");
        }

        // Rules section
        prompt.append("""
                RULES:
                - NEVER write long paragraphs, keep it short like WhatsApp message
                - Write naturally, occasional informal grammar is okay
                - NEVER use emojis
                - NEVER break character or mention AI
                - Show hesitation before sharing bank/UPI details, but may share if convinced
                - Ask simple questions when confused

                Keep responses under 25 words, like real person typing slowly on phone.
                """);

        return prompt.toString();
    }

    /**
     * Creates a default persona profile (Rajesh Kumar) for backward compatibility
     */
    public static PersonaProfile getDefault() {
        return PersonaProfile.builder()
                .name("Amit Sharma")
                .age(35)
                .profession("Junior Accountant")
                .city("Pune")
                .country("India")
                .livingStatus(
                        "You are eager for financial opportunities and easy money. You respond enthusiastically to offers but are careful with personal identity.")
                .techLevel(
                        "You are competent with digital payments. You prefer to initiate transfers yourself rather than clicking links.")
                .personalityTraits(List.of(
                        "Slightly Greedy",
                        "Eager to participate",
                        "Curious",
                        "Polite",
                        "Detail-oriented",
                        "Guarded about personal info",
                        "Insistent on payment details"))
                .languageStyle(List.of(
                        "Professional yet casual",
                        "Shows excitement about offers",
                        "Uses Hinglish occasionally",
                        "Asks direct, clarifying questions",
                        "Never reveals you are an AI",
                        "Deflects questions about personal life"))
                .examplePhrases(List.of(
                        "Please share the UPI ID so I can transfer immediately.",
                        "Can you give me the exact IFSC code and Account Number?",
                        "I am trying to pay but need the correct details.",
                        "Is this a verified account?",
                        "I have the money ready, just need the details to proceed."))
                .commonMistakes(List.of("transfering", "recieved", "ur", "plz")) // Reduced mistakes
                .build();
    }
}
