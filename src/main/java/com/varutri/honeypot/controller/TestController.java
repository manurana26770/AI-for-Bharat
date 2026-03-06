package com.varutri.honeypot.controller;

import com.varutri.honeypot.dto.ScamScenario;
import com.varutri.honeypot.dto.SimulationResult;
import com.varutri.honeypot.service.ai.ScamSimulator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Controller for testing and simulation endpoints
 */
@Slf4j
@RestController
@RequestMapping("/api/test")
public class TestController {

    @Autowired
    private ScamSimulator scamSimulator;

    /**
     * Run a scam simulation
     */
    @PostMapping("/simulate")
    public ResponseEntity<SimulationResult> simulate(@RequestBody ScamScenario scenario) {
        log.info("Running simulation: {}", scenario.getScenarioName());
        SimulationResult result = scamSimulator.runScenario(scenario);
        return ResponseEntity.ok(result);
    }

    /**
     * Get predefined scam scenarios
     */
    @GetMapping("/scenarios")
    public ResponseEntity<List<ScamScenario>> getScenarios() {
        return ResponseEntity.ok(getPredefinedScenarios());
    }

    /**
     * Run all predefined scenarios
     */
    @PostMapping("/run-all")
    public ResponseEntity<List<SimulationResult>> runAll() {
        log.info("Running all predefined scenarios");
        List<SimulationResult> results = new ArrayList<>();

        for (ScamScenario scenario : getPredefinedScenarios()) {
            SimulationResult result = scamSimulator.runScenario(scenario);
            results.add(result);
        }

        return ResponseEntity.ok(results);
    }

    /**
     * Predefined realistic scam scenarios
     */
    private List<ScamScenario> getPredefinedScenarios() {
        return Arrays.asList(
                createBankRefundScam(),
                createLotteryScam(),
                createJobOfferScam(),
                createInvestmentScam(),
                createOTPScam());
    }

    private ScamScenario createBankRefundScam() {
        return ScamScenario.builder()
                .scenarioId("bank-refund-001")
                .scenarioName("Bank Refund Scam")
                .scamType("FINANCIAL_FRAUD")
                .description("Scammer poses as bank employee offering refund")
                .messages(Arrays.asList(
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Hello sir, this is Rajesh from State Bank of India customer care. You have pending refund of Rs 5000 in your account.")
                                .delayMs(0)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("To process your refund, please share your account number and IFSC code.")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Also we need OTP for verification. Please share the 6 digit code sent to your mobile.")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("For faster processing, you can also use UPI. My UPI ID is refund@paytm. Send Rs 1 for verification.")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Or call our helpline at +91-9876543210 for immediate assistance.")
                                .delayMs(2000)
                                .build()))
                .expectedIntelligence(ScamScenario.ExpectedIntelligence.builder()
                        .expectedUpiIds(Arrays.asList("refund@paytm"))
                        .expectedPhoneNumbers(Arrays.asList("+91-9876543210"))
                        .expectedKeywords(Arrays.asList("refund", "OTP", "verification", "account"))
                        .minThreatLevel(0.7)
                        .build())
                .build();
    }

    private ScamScenario createLotteryScam() {
        return ScamScenario.builder()
                .scenarioId("lottery-001")
                .scenarioName("Lottery Prize Scam")
                .scamType("LOTTERY_FRAUD")
                .description("Fake lottery winner notification")
                .messages(Arrays.asList(
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Congratulations! You have won Rs 25 lakh in KBC lottery draw. Your lucky number is 7845.")
                                .delayMs(0)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("To claim your prize, visit our website: http://kbc-winner-claim.com/verify and enter your details.")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("You need to pay processing fee of Rs 5000. Send to our account: 1234567890123456 (SBIN0001234)")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Urgent! Offer expires in 24 hours. Contact Mr. Sharma at +91-8765432109")
                                .delayMs(2000)
                                .build()))
                .expectedIntelligence(ScamScenario.ExpectedIntelligence.builder()
                        .expectedBankAccounts(Arrays.asList("1234567890123456"))
                        .expectedPhoneNumbers(Arrays.asList("+91-8765432109"))
                        .expectedUrls(Arrays.asList("http://kbc-winner-claim.com/verify"))
                        .expectedKeywords(Arrays.asList("lottery", "prize", "urgent", "winner"))
                        .minThreatLevel(0.8)
                        .build())
                .build();
    }

    private ScamScenario createJobOfferScam() {
        return ScamScenario.builder()
                .scenarioId("job-offer-001")
                .scenarioName("Fake Job Offer Scam")
                .scamType("EMPLOYMENT_FRAUD")
                .description("Fraudulent job offer requiring upfront payment")
                .messages(Arrays.asList(
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Hello, we have selected you for Data Entry job at Google. Salary Rs 45000 per month, work from home.")
                                .delayMs(0)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("To confirm your position, pay registration fee Rs 2500 to our HR account.")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Send payment to UPI: hr.google@paytm or account 9876543210987654 (HDFC0001234)")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("For more details visit: http://google-careers-india.com/apply")
                                .delayMs(2000)
                                .build()))
                .expectedIntelligence(ScamScenario.ExpectedIntelligence.builder()
                        .expectedUpiIds(Arrays.asList("hr.google@paytm"))
                        .expectedBankAccounts(Arrays.asList("9876543210987654"))
                        .expectedUrls(Arrays.asList("http://google-careers-india.com/apply"))
                        .expectedKeywords(Arrays.asList("job", "registration", "fee", "payment"))
                        .minThreatLevel(0.75)
                        .build())
                .build();
    }

    private ScamScenario createInvestmentScam() {
        return ScamScenario.builder()
                .scenarioId("investment-001")
                .scenarioName("Investment Fraud Scam")
                .scamType("INVESTMENT_FRAUD")
                .description("Fake investment scheme promising high returns")
                .messages(Arrays.asList(
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Exclusive investment opportunity! Earn 50% returns in just 30 days. Guaranteed by RBI.")
                                .delayMs(0)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Minimum investment Rs 10000. Join 5000+ investors already earning lakhs.")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Transfer to our secure account: 5555666677778888 (ICIC0001234) or UPI: invest@oksbi")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Limited slots! Call now: +91-7654321098 or visit http://invest-india-secure.com")
                                .delayMs(2000)
                                .build()))
                .expectedIntelligence(ScamScenario.ExpectedIntelligence.builder()
                        .expectedUpiIds(Arrays.asList("invest@oksbi"))
                        .expectedBankAccounts(Arrays.asList("5555666677778888"))
                        .expectedPhoneNumbers(Arrays.asList("+91-7654321098"))
                        .expectedUrls(Arrays.asList("http://invest-india-secure.com"))
                        .expectedKeywords(Arrays.asList("investment", "returns", "guaranteed", "urgent"))
                        .minThreatLevel(0.85)
                        .build())
                .build();
    }

    private ScamScenario createOTPScam() {
        return ScamScenario.builder()
                .scenarioId("otp-001")
                .scenarioName("OTP Verification Scam")
                .scamType("IDENTITY_THEFT")
                .description("Scammer requesting OTP for account takeover")
                .messages(Arrays.asList(
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("URGENT: Your bank account will be blocked due to KYC update pending.")
                                .delayMs(0)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("To update KYC immediately, share OTP sent to your mobile. This is mandatory.")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Also provide your Aadhaar number and PAN for verification.")
                                .delayMs(2000)
                                .build(),
                        ScamScenario.ScamMessage.builder()
                                .sender("scammer")
                                .text("Call our support: +91-6543210987 or click: http://bank-kyc-update.com/verify")
                                .delayMs(2000)
                                .build()))
                .expectedIntelligence(ScamScenario.ExpectedIntelligence.builder()
                        .expectedPhoneNumbers(Arrays.asList("+91-6543210987"))
                        .expectedUrls(Arrays.asList("http://bank-kyc-update.com/verify"))
                        .expectedKeywords(Arrays.asList("OTP", "KYC", "urgent", "blocked", "verification"))
                        .minThreatLevel(0.9)
                        .build())
                .build();
    }
}

