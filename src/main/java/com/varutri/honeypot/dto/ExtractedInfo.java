package com.varutri.honeypot.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

/**
 * DTO for storing extracted intelligence from scam messages
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class ExtractedInfo {
    private List<String> upiIds = new ArrayList<>();
    private List<String> bankAccountNumbers = new ArrayList<>();
    private List<String> ifscCodes = new ArrayList<>();
    private List<String> phoneNumbers = new ArrayList<>();
    private List<String> urls = new ArrayList<>();
    private List<String> emails = new ArrayList<>();

    // Scam detection info
    private String scamType;
    private double threatLevel;
    private List<String> suspiciousKeywords = new ArrayList<>();
}
