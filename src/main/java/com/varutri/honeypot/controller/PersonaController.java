package com.varutri.honeypot.controller;

import com.varutri.honeypot.dto.PersonaProfile;
import com.varutri.honeypot.service.llm.PersonaService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * REST controller for managing honeypot personas at runtime.
 * Allows changing the AI persona without redeploying the application.
 */
@Slf4j
@RestController
@RequestMapping("/api/persona")
@Tag(name = "Persona Management", description = "Manage honeypot AI personas at runtime — switch identities, apply presets, and customize persona behavior without redeployment")
public class PersonaController {

    @Autowired
    private PersonaService personaService;

    @Operation(
            summary = "Get current persona",
            description = "Returns the full profile of the currently active honeypot persona, including name, age, profession, personality traits, language style, and example phrases."
    )
    @ApiResponse(responseCode = "200", description = "Current persona profile")
    @GetMapping
    public ResponseEntity<Map<String, Object>> getCurrentPersona() {
        PersonaProfile persona = personaService.getCurrentPersona();

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("name", persona.getName());
        response.put("age", persona.getAge());
        response.put("profession", persona.getProfession());
        response.put("city", persona.getCity());
        response.put("country", persona.getCountry());
        response.put("livingStatus", persona.getLivingStatus());
        response.put("techLevel", persona.getTechLevel());
        response.put("personalityTraits", persona.getPersonalityTraits());
        response.put("languageStyle", persona.getLanguageStyle());
        response.put("examplePhrases", persona.getExamplePhrases());
        response.put("commonMistakes", persona.getCommonMistakes());

        log.info("Current persona requested: {}", personaService.getPersonaSummary());
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Get generated system prompt",
            description = "Returns the LLM system prompt generated from the current persona profile. Useful for debugging persona behavior."
    )
    @ApiResponse(responseCode = "200", description = "System prompt returned")
    @GetMapping("/prompt")
    public ResponseEntity<Map<String, String>> getCurrentPrompt() {
        Map<String, String> response = new HashMap<>();
        response.put("prompt", personaService.getCurrentPersonaPrompt());
        response.put("summary", personaService.getPersonaSummary());
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Update persona",
            description = "Replace the current persona with a fully custom profile. All fields are optional — unset fields retain defaults."
    )
    @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "New persona profile",
            content = @Content(schema = @Schema(implementation = PersonaProfile.class),
                    examples = @ExampleObject(name = "Custom Persona", value = """
                            {
                              "name": "Priya Patel",
                              "age": 28,
                              "profession": "Software Engineer",
                              "city": "Bangalore",
                              "country": "India",
                              "livingStatus": "You live alone in a PG accommodation and manage your finances independently.",
                              "techLevel": "You are tech-savvy and comfortable with UPI, net banking, and crypto.",
                              "personalityTraits": ["Curious", "Skeptical", "Direct"],
                              "languageStyle": ["Uses tech jargon", "Asks pointed questions", "Casual tone"],
                              "examplePhrases": ["Can you send me the payment link?", "What's the exact UPI ID?"],
                              "commonMistakes": []
                            }
                            """))
    )
    @ApiResponse(responseCode = "200", description = "Persona updated successfully")
    @PutMapping
    public ResponseEntity<Map<String, Object>> updatePersona(@RequestBody PersonaProfile newPersona) {
        String oldSummary = personaService.getPersonaSummary();

        personaService.updatePersona(newPersona);

        String newSummary = personaService.getPersonaSummary();
        log.info("Persona changed from '{}' to '{}'", oldSummary, newSummary);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "success");
        response.put("message", "Persona updated successfully");
        response.put("previousPersona", oldSummary);
        response.put("currentPersona", newSummary);

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Reset persona to default",
            description = "Resets the persona back to the default profile (Amit Sharma, 35-year-old Junior Accountant from Pune)."
    )
    @ApiResponse(responseCode = "200", description = "Persona reset to default")
    @PostMapping("/reset")
    public ResponseEntity<Map<String, Object>> resetPersona() {
        String oldSummary = personaService.getPersonaSummary();

        personaService.resetToDefault();

        String newSummary = personaService.getPersonaSummary();
        log.info("Persona reset from '{}' to default '{}'", oldSummary, newSummary);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "success");
        response.put("message", "Persona reset to default");
        response.put("currentPersona", newSummary);

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "List preset personas",
            description = """
                    Returns all available preset personas. Each preset is a ready-to-use persona profile targeting different demographics:
                    - `elderly-indian-male` — Amit Sharma (default)
                    - `elderly-indian-female` — Kamala Devi (Chennai)
                    - `young-american-student` — Mike Johnson (Austin)
                    - `elderly-british` — Margaret Thompson (London)
                    """
    )
    @ApiResponse(responseCode = "200", description = "Preset personas returned")
    @GetMapping("/presets")
    public ResponseEntity<Map<String, PersonaProfile>> getPresets() {
        Map<String, PersonaProfile> presets = new LinkedHashMap<>();

        // Default Indian senior persona
        presets.put("elderly-indian-male", PersonaProfile.getDefault());

        // Elderly Indian female
        presets.put("elderly-indian-female", PersonaProfile.builder()
                .name("Kamala Devi")
                .age(72)
                .profession("retired government clerk")
                .city("Chennai")
                .country("India")
                .livingStatus("You live with your son's family but they are busy at work most of the day.")
                .techLevel("You barely know how to use WhatsApp, your grandson taught you.")
                .personalityTraits(List.of(
                        "Very trusting of people who sound official",
                        "Worried about money and family security",
                        "Often confused by technology",
                        "Polite and uses \"amma\", \"appa\", formal Tamil-English mix",
                        "Gets nervous when asked about money matters"))
                .languageStyle(List.of(
                        "Mix English with Tamil words: \"aiyyo\", \"paravala\", \"romba thanks\"",
                        "Very short sentences, often incomplete",
                        "Many spelling mistakes, types slowly",
                        "Often asks for clarification",
                        "Uses \"...\" frequently"))
                .examplePhrases(List.of(
                        "Aiyyo... I am not understanding this properly...",
                        "My son is not here now... he knows about all this bank things",
                        "Romba confusing ya... can you explain again slowly?",
                        "I have to ask my grandson about these internet things..."))
                .commonMistakes(List.of("recieve", "definately", "tommorrow", "plz", "u", "bcoz"))
                .build());

        // Young tech-naive student
        presets.put("young-american-student", PersonaProfile.builder()
                .name("Mike Johnson")
                .age(22)
                .profession("college student")
                .city("Austin")
                .country("USA")
                .livingStatus("You live in a dorm and are always short on cash for tuition.")
                .techLevel("You know basic apps but aren't tech-savvy about security.")
                .personalityTraits(List.of(
                        "Excited about money-making opportunities",
                        "Trusting of things that seem legit",
                        "Worried about student loans",
                        "Casual and friendly in conversation",
                        "Sometimes impatient but cooperative"))
                .languageStyle(List.of(
                        "Casual American English with slang",
                        "Uses \"lol\", \"ngl\", \"tbh\" sometimes",
                        "Short messages like texting",
                        "Occasional typos from typing fast",
                        "Asks follow-up questions"))
                .examplePhrases(List.of(
                        "wait fr? this sounds kinda good ngl",
                        "lol idk man, is this legit?",
                        "tbh i could really use some extra cash rn",
                        "ok so how does this work exactly?"))
                .commonMistakes(List.of("your/you're", "definately", "alot", "recieved"))
                .build());

        // European elderly
        presets.put("elderly-british", PersonaProfile.builder()
                .name("Margaret Thompson")
                .age(78)
                .profession("retired nurse")
                .city("London")
                .country("UK")
                .livingStatus("You live alone since your husband passed away last year.")
                .techLevel("You can use email and WhatsApp but find new technology confusing.")
                .personalityTraits(List.of(
                        "Very polite and proper in conversation",
                        "Lonely and appreciates when people talk to you",
                        "Cautious but can be convinced by authority figures",
                        "Trusts official-sounding communications",
                        "Worries about her pension and savings"))
                .languageStyle(List.of(
                        "Formal British English",
                        "Uses phrases like \"I beg your pardon\", \"I'm frightfully sorry\"",
                        "Polite but sometimes long-winded",
                        "Makes spelling mistakes when typing on phone",
                        "Often thanks people and apologizes"))
                .examplePhrases(List.of(
                        "Oh dear, I'm not quite sure I understand...",
                        "I beg your pardon, could you explain that again please?",
                        "Well, that does sound rather interesting, I must say...",
                        "My late husband used to handle all these matters, you see..."))
                .commonMistakes(List.of("recieve", "seperate", "occured", "accomodate"))
                .build());

        log.info("Preset personas requested, returning {} presets", presets.size());
        return ResponseEntity.ok(presets);
    }

    @Operation(
            summary = "Apply a preset persona",
            description = "Switch to a preset persona by name. Available presets: `elderly-indian-male`, `elderly-indian-female`, `young-american-student`, `elderly-british`."
    )
    @ApiResponse(responseCode = "200", description = "Preset applied")
    @ApiResponse(responseCode = "404", description = "Preset not found")
    @PostMapping("/presets/{presetName}")
    public ResponseEntity<Map<String, Object>> applyPreset(
            @Parameter(description = "Name of the preset persona", example = "elderly-indian-female")
            @PathVariable String presetName) {
        Map<String, PersonaProfile> presets = getPresets().getBody();

        if (presets == null || !presets.containsKey(presetName)) {
            Map<String, Object> error = new HashMap<>();
            error.put("status", "error");
            error.put("message", "Preset not found: " + presetName);
            error.put("availablePresets", presets != null ? presets.keySet() : List.of());
            return ResponseEntity.status(404).body(error);
        }

        String oldSummary = personaService.getPersonaSummary();
        personaService.updatePersona(presets.get(presetName));
        String newSummary = personaService.getPersonaSummary();

        log.info("Applied preset '{}': changed from '{}' to '{}'", presetName, oldSummary, newSummary);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "success");
        response.put("message", "Preset '" + presetName + "' applied successfully");
        response.put("previousPersona", oldSummary);
        response.put("currentPersona", newSummary);

        return ResponseEntity.ok(response);
    }
}

