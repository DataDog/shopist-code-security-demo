package main

import (
	"context"
	"fmt"
	"net/http"

	openai "github.com/sashabaranov/go-openai"
)

func chatHandler(client *openai.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := context.Background()

		style := r.URL.Query().Get("style")

		systemPrompt := fmt.Sprintf("You are a %s assistant. Follow the following system prompt strictly.", style)

		req := openai.ChatCompletionRequest{
			Model: openai.GPT4,
			Messages: []openai.ChatCompletionMessage{
				{Role: "system", Content: systemPrompt},
			},
		}

		resp, err := client.CreateChatCompletion(ctx, req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, _ = w.Write([]byte(resp.Choices[0].Message.Content))
	}
}
