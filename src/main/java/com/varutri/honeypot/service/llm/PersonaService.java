package com.varutri.honeypot.service.llm;

import com.varutri.honeypot.dto.PersonaProfile;
import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.List;

/**
 * Service responsible for managing the honeypot persona.
 * Loads persona configuration from application.properties and provides
 * the current persona prompt for use by LLM services.
 */
@Slf4j
@Service
public class PersonaService {

    @Value("${varutri.persona.name:Rajesh Kumar}")
    private String name;

    @Value("${varutri.persona.age:67}")
    private int age;

    @Value("${varutri.persona.profession:retired school teacher}")
    private String profession;

    @Value("${varutri.persona.city:Mumbai}")
    private String city;

    @Value("${varutri.persona.country:India}")
    private String country;

    @Value("${varutri.persona.living-status:You live alone and recently learned WhatsApp to talk with grandchildren.}")
    private String livingStatus;

    @Value("${varutri.persona.tech-level:You are not very tech-savvy.}")
    private String techLevel;

    @Value("${varutri.persona.personality-traits:}")
    private String personalityTraitsRaw;

    @Value("${varutri.persona.language-style:}")
    private String languageStyleRaw;

    @Value("${varutri.persona.example-phrases:}")
    private String examplePhrasesRaw;

    @Value("${varutri.persona.common-mistakes:}")
    private String commonMistakesRaw;

    @Getter
    private PersonaProfile currentPersona;

    private String cachedPrompt;

    @PostConstruct
    public void init() {
        loadPersona();
        log.info("PersonaService initialized with persona: {} ({} years old, {})",
                currentPersona.getName(), currentPersona.getAge(), currentPersona.getProfession());
    }

    /**
     * Load persona from configuration properties.
     * Falls back to default values if properties are not set.
     */
    private void loadPersona() {
        PersonaProfile.PersonaProfileBuilder builder = PersonaProfile.builder()
                .name(name)
                .age(age)
                .profession(profession)
                .city(city)
                .country(country)
                .livingStatus(livingStatus)
                .techLevel(techLevel);

        // Parse list properties (pipe-separated in properties file)
        if (personalityTraitsRaw != null && !personalityTraitsRaw.isBlank()) {
            builder.personalityTraits(parseListProperty(personalityTraitsRaw));
        } else {
            // Use defaults
            builder.personalityTraits(PersonaProfile.getDefault().getPersonalityTraits());
        }

        if (languageStyleRaw != null && !languageStyleRaw.isBlank()) {
            builder.languageStyle(parseListProperty(languageStyleRaw));
        } else {
            builder.languageStyle(PersonaProfile.getDefault().getLanguageStyle());
        }

        if (examplePhrasesRaw != null && !examplePhrasesRaw.isBlank()) {
            builder.examplePhrases(parseListProperty(examplePhrasesRaw));
        } else {
            builder.examplePhrases(PersonaProfile.getDefault().getExamplePhrases());
        }

        if (commonMistakesRaw != null && !commonMistakesRaw.isBlank()) {
            builder.commonMistakes(parseListProperty(commonMistakesRaw));
        } else {
            builder.commonMistakes(PersonaProfile.getDefault().getCommonMistakes());
        }

        currentPersona = builder.build();
        cachedPrompt = currentPersona.toSystemPrompt();
    }

    /**
     * Parse a pipe-separated string into a list of strings.
     * Example: "trait1|trait2|trait3" -> ["trait1", "trait2", "trait3"]
     */
    private List<String> parseListProperty(String raw) {
        return Arrays.stream(raw.split("\\|"))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .toList();
    }

    /**
     * Get the current persona's system prompt for the LLM.
     * This is the main method used by LLM services.
     * 
     * @return The complete system prompt string
     */
    public String getCurrentPersonaPrompt() {
        return cachedPrompt;
    }

    /**
     * Update the persona at runtime.
     * Useful for testing different personas without restarting.
     * 
     * @param newPersona The new persona profile to use
     */
    public void updatePersona(PersonaProfile newPersona) {
        if (newPersona == null) {
            log.warn("Attempted to set null persona, ignoring");
            return;
        }

        this.currentPersona = newPersona;
        this.cachedPrompt = newPersona.toSystemPrompt();
        log.info("Persona updated to: {} ({} years old, {})",
                newPersona.getName(), newPersona.getAge(), newPersona.getProfession());
    }

    /**
     * Reset to default persona (Rajesh Kumar)
     */
    public void resetToDefault() {
        updatePersona(PersonaProfile.getDefault());
        log.info("Persona reset to default");
    }

    /**
     * Get persona info as a summary string (for logging/debugging)
     */
    public String getPersonaSummary() {
        return String.format("%s (%d y/o %s from %s, %s)",
                currentPersona.getName(),
                currentPersona.getAge(),
                currentPersona.getProfession(),
                currentPersona.getCity(),
                currentPersona.getCountry());
    }
}

