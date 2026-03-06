# Varutri Honeypot Terminal Dashboard

## Hacker-Style Monitoring Interface

A cyberpunk-themed terminal dashboard for monitoring scam conversations in real-time.

## Features

### Left Panel: Conversation Monitor
- Live chat feed showing scammer messages and AI responses
- Color-coded messages (Red = Scammer, Green = AI, Gray = System)
- Input field to simulate scammer messages
- Scrollable conversation history

### Right Panel: Threat Analysis
- **Threat Meter**: Visual bar showing threat level (0-100%)
  - Green (0-40%): Safe
  - Yellow (40-70%): Medium Threat
  - Red (70-100%): High Threat
- **Scam Type Detection**: Shows detected scam category
- **Intelligence Extracted**: Real-time list of:
  -  UPI IDs
  -  Bank Accounts
  -  Phone Numbers
  -  Phishing URLs
  -  Suspicious Keywords
- **Session Stats**: Message count and turn count
- **Quick Actions**:
  - Run Tests
  - Generate Report
  - Reset Session

## How to Use

### 1. Start Backend
```bash
cd /Users/sahilkumarsingh/Desktop/Varutri-Honeypot
java -jar target/honeypot-1.0.0.jar
```

### 2. Open Frontend
```bash
cd frontend
open index.html
# Or just double-click index.html
```

### 3. Simulate Scammer
Type scammer messages in the input field:
```
You won 10 lakh rupees! Send to 9876543210@paytm
```

Watch as:
- AI responds with elderly persona
- Threat level increases
- Intelligence gets extracted
- Stats update in real-time

### 4. Run Tests
Click "RUN TESTS" to execute all 5 scam scenarios automatically

### 5. Generate Report
Click "GENERATE REPORT" to create government report for current session

## Design

- **Theme**: Cyberpunk/Matrix green terminal
- **Font**: Courier New (monospace)
- **Colors**:
  - Background: Dark blue (#0a0e27)
  - Primary: Matrix green (#00ff41)
  - Danger: Red (#ff4444)
  - Warning: Yellow (#ffff00)
- **Animations**:
  - Pulsing status indicator
  - Scanning threat meter
  - Glowing text effects
  - Smooth message transitions

## API Integration

Connects to your Spring Boot backend:
- `POST /api/chat` - Send scammer messages
- `GET /api/evidence/{sessionId}` - Get threat data
- `POST /api/test/run-all` - Run test scenarios
- `POST /api/report/manual` - Generate reports
- `GET /api/report/stats` - Get statistics

## Files

```
frontend/
├── index.html    # Main dashboard structure
├── style.css     # Cyberpunk styling
├── app.js        # API integration & logic
└── README.md     # This file
```

## Customization

### Change API URL
Edit `app.js`:
```javascript
const API_URL = 'https://your-render-url.com';
```

### Adjust Colors
Edit `style.css`:
```css
--primary-color: #00ff41;  /* Change to your color */
```

## Demo Flow

1. Type: `Hello sir, you won lottery of 50 lakh rupees!`
2. Watch AI respond: `Arrey beta! 50 lakh? But I am old person...`
3. Type: `Send OTP to 9876543210@paytm to claim`
4. See threat level jump to 80%
5. See UPI ID extracted in right panel
6. Click "GENERATE REPORT"

## Screenshots

The terminal shows:
- Live conversation on left
- Animated threat meter on right
- Real-time intelligence extraction
- Glowing green matrix aesthetic

Perfect for hackathon demos! 
