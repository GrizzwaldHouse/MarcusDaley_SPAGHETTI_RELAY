#ifndef QUOTE_SYSTEM_H
#define QUOTE_SYSTEM_H

#include <vector>
#include <random>
#include <ctime>
#include <iostream>
#include <string>

class QuoteSystem {
public:
    enum class MessageType {
        SUCCESS,
        WARNING,
        ERROR1,
        INFO,
        DEBUG
    };

    QuoteSystem() {
        srand(static_cast<unsigned int>(time(nullptr)));
        InitializeQuotes();
    }

    void Log(const std::string& message, MessageType type) {
        switch (type) {
        case MessageType::SUCCESS:
            std::cout << "\n[SUCCESS] " << message << "\n    \""
                << GetRandomQuote(successQuotes) << "\"\n" << std::endl;
            break;
        case MessageType::WARNING:
            std::cout << "\n[WARNING] " << message << "\n    \""
                << GetRandomQuote(warningQuotes) << "\"\n" << std::endl;
            break;
        case MessageType::ERROR1:
            std::cout << "\n[ERROR] " << message << "\n    \""
                << GetRandomQuote(errorQuotes) << "\"\n" << std::endl;
            break;
        case MessageType::INFO:
            std::cout << "\n[INFO] " << message << "\n    \""
                << GetRandomQuote(infoQuotes) << "\"\n" << std::endl;
            break;
        case MessageType::DEBUG:
            std::cout << "\n[DEBUG] " << message << "\n    \""
                << GetRandomQuote(debugQuotes) << "\"\n" << std::endl;
            break;
        }
    }

    // Shutdown method to clean up resources if needed
    void Shutdown() {
        successQuotes.clear();
        warningQuotes.clear();
        errorQuotes.clear();
        infoQuotes.clear();
        debugQuotes.clear();
        std::cout << "[INFO] Quote system shut down." << std::endl;
    }

private:
    std::vector<std::string> successQuotes;
    std::vector<std::string> warningQuotes;
    std::vector<std::string> errorQuotes;
    std::vector<std::string> infoQuotes;
    std::vector<std::string> debugQuotes;

    std::string GetRandomQuote(const std::vector<std::string>& quotes) {
        if (quotes.empty()) return "No quotes available";
        return quotes[rand() % quotes.size()];
    }

    void InitializeQuotes() {
        // Success quotes
        successQuotes = {
            "Mischief managed! - Harry Potter",
            "I solemnly swear that I am up to good! - Harry Potter",
            "Curiouser and curiouser! - Alice in Wonderland",
            "Believe it! - Naruto",
            "You don't always need a plan. - Maya Angelou"
        };

        // Warning quotes
        warningQuotes = {
            "I must not tell lies. - Harry Potter",
            "Constant vigilance! - Mad-Eye Moody",
            "We're all mad here. - Cheshire Cat",
            "Off with their heads! - Queen of Hearts"
        };

        // Error quotes
        errorQuotes = {
            "Alas! Earwax! - Albus Dumbledore",
            "Not my daughter, you glitch! - Molly Weasley",
            "I'm late, I'm late, for a very important date! - White Rabbit"
        };

        // Info quotes
        infoQuotes = {
            "It does not do to dwell on dreams and forget to live. - Albus Dumbledore",
            "Follow the White Rabbit. - Alice in Wonderland",
            "That's my ninja way! - Naruto"
        };

        // Debug quotes
        debugQuotes = {
            "I've got the Trace Charm on me! - Harry Potter",
            "Begin at the beginning and go on till you come to the end; then stop. - King of Hearts"
        };
    }
};

// Convenience functions for logging
inline void LogSuccess(const std::string& message) {
    QuoteSystem quoteSystem;
    quoteSystem.Log(message, QuoteSystem::MessageType::SUCCESS);
}

inline void LogWarning(const std::string& message) {
    QuoteSystem quoteSystem;
    quoteSystem.Log(message, QuoteSystem::MessageType::WARNING);
}

inline void LogError(const std::string& message) {
    QuoteSystem quoteSystem;
    quoteSystem.Log(message, QuoteSystem::MessageType::ERROR1);
}

inline void LogInfo(const std::string& message) {
    QuoteSystem quoteSystem;
    quoteSystem.Log(message, QuoteSystem::MessageType::INFO);
}

inline void LogDebug(const std::string& message) {
    QuoteSystem quoteSystem;
    quoteSystem.Log(message, QuoteSystem::MessageType::DEBUG);
}

#endif // QUOTE_SYSTEM_H