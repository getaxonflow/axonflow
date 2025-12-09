package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/getaxonflow/axonflow-sdk-go"
)

// ConversationMemory stores the chat history
type ConversationMemory struct {
	History []Message
}

// Message represents a single chat message
type Message struct {
	Role    string // "user" or "assistant"
	Content string
}

func main() {
	agentURL := os.Getenv("AXONFLOW_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080"
	}

	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")
	if licenseKey == "" {
		log.Fatal("❌ AXONFLOW_LICENSE_KEY must be set in .env file")
	}

	client := axonflow.NewClient(axonflow.AxonFlowConfig{
		AgentURL:   agentURL,
		LicenseKey: licenseKey,
	})

	fmt.Println("✅ Connected to AxonFlow")
	fmt.Println("💬 Chatbot with Memory - Interactive Demo")
	fmt.Println()
	fmt.Println("This chatbot remembers your conversation history.")
	fmt.Println("Try telling it your name, preferences, and ask it to recall them!")
	fmt.Println("Type 'exit' to quit.")
	fmt.Println()

	// Initialize conversation memory
	memory := &ConversationMemory{
		History: []Message{},
	}

	// System prompt to establish chatbot personality
	systemPrompt := "You are a helpful and friendly assistant with perfect memory. " +
		"You remember everything the user tells you in this conversation. " +
		"When users share information (name, preferences, facts), acknowledge and remember it. " +
		"Reference previous parts of the conversation naturally."

	// Add system prompt to memory
	memory.History = append(memory.History, Message{
		Role:    "system",
		Content: systemPrompt,
	})

	scanner := bufio.NewScanner(os.Stdin)

	for {
		// Get user input
		fmt.Print("👤 You: ")
		if !scanner.Scan() {
			break
		}

		userInput := strings.TrimSpace(scanner.Text())

		if userInput == "" {
			continue
		}

		if strings.ToLower(userInput) == "exit" {
			fmt.Println("👋 Goodbye! Thanks for chatting!")
			break
		}

		// Add user message to memory
		memory.History = append(memory.History, Message{
			Role:    "user",
			Content: userInput,
		})

		// Build context from conversation history
		context := buildContext(memory)

		// Query AxonFlow with full conversation context
		query := fmt.Sprintf("Conversation history:\n%s\n\nUser's latest message: %s\n\n"+
			"Respond naturally, referencing previous parts of the conversation when relevant.",
			context, userInput)

		response, err := client.ExecuteQuery("user-123", query, "chat", map[string]interface{}{"model": "gpt-4"})
		if err != nil {
			log.Printf("❌ Error: %v\n", err)
			continue
		}

		// Add assistant response to memory
		memory.History = append(memory.History, Message{
			Role:    "assistant",
			Content: fmt.Sprintf("%v", response.Data),
		})

		// Display response
		fmt.Printf("🤖 Bot: %s\n\n", response.Data)
	}

	// Show conversation summary
	fmt.Println()
	fmt.Println("📊 Conversation Summary:")
	fmt.Printf("Total messages exchanged: %d\n", len(memory.History)-1) // -1 for system prompt
	fmt.Println("✅ Chatbot memory demonstration complete")
	fmt.Println("💡 This example shows stateful conversation with full history tracking")
}

// buildContext creates a formatted context string from conversation history
func buildContext(memory *ConversationMemory) string {
	var context strings.Builder

	for i, msg := range memory.History {
		if msg.Role == "system" {
			continue // Skip system prompt in context display
		}

		if i > 0 {
			context.WriteString("\n")
		}

		if msg.Role == "user" {
			context.WriteString(fmt.Sprintf("User: %s", msg.Content))
		} else if msg.Role == "assistant" {
			context.WriteString(fmt.Sprintf("Assistant: %s", msg.Content))
		}
	}

	return context.String()
}
