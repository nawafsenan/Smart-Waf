# SWAF (Smart Web Application Firewall)

A comprehensive reverse proxy solution with built-in Web Application Firewall (WAF) capabilities, SSL certificate management, and machine learning-based threat detection.

## WAF Features

### Security Rules
- **SQL Injection Detection**: Blocks common SQL injection patterns
- **XSS Protection**: Prevents cross-site scripting attacks
- **Path Traversal Protection**: Blocks directory traversal attempts
- **Command Injection**: Prevents command injection attacks

### Session Management
- **Rate Limiting**: Limits requests per time window
- **Session Tracking**: Monitors user sessions
- **Blocked Session Handling**: Manages blocked sessions
- **Session Analytics**: Detailed session statistics

### Header Manipulation
- **Custom Headers**: Add custom security headers
- **Header Removal**: Remove sensitive headers (e.g., Server header)
- **Header Replacement**: Replace headers for security

## Monitoring and Logging

### Elasticsearch Integration
- **Request Logging**: All requests are logged to Elasticsearch
- **Response Logging**: Response data is stored for analysis
- **Session Tracking**: Session data is indexed for monitoring
- **Real-time Analytics**: Query logs for security analysis

### Session Analytics
- **Session Statistics**: View session metrics and patterns
- **Attack Detection**: Identify attack patterns in sessions
- **User Behavior**: Track user behavior across sessions
- **Performance Metrics**: Monitor system performance

## Deep Learning Detection

The system includes a pre-trained CNN-LSTM model for threat detection:
- **Model File**: `cnn-lstm_character-level(98.9)(augmanted).h5`
- **Tokenizer**: `token-150-2000(98.9)(augmanted).pkl`
- **Accuracy**: 98.9% on augmented dataset
- **Real-time Analysis**: Analyzes requests in real-time
