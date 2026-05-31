package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// IntelItem is a single community-reported security item from a public source.
type IntelItem struct {
	Source string // "GitHub", "HackerNews"
	Date   string // YYYY-MM-DD or empty
	Title  string
	URL    string
}

// FetchCommunityIntel queries GitHub and HackerNews for recent OpenClaw security
// discussions and returns up to 8 items. Failures are silently swallowed — the
// caller proceeds with an empty slice rather than aborting the scan.
func FetchCommunityIntel(ctx context.Context) []IntelItem {
	type fetcher func(context.Context) []IntelItem
	sources := []fetcher{fetchGitHubIntel, fetchHNIntel}

	var items []IntelItem
	for _, fn := range sources {
		sub, cancel := context.WithTimeout(ctx, 10*time.Second)
		got := fn(sub)
		cancel()
		items = append(items, got...)
	}
	if len(items) > 8 {
		items = items[:8]
	}
	return items
}

func fetchGitHubIntel(ctx context.Context) []IntelItem {
	const endpoint = "https://api.github.com/search/issues" +
		"?q=openclaw+security&sort=updated&per_page=5"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/vnd.github.v3+json")
	req.Header.Set("User-Agent", "anvil-scanner/security-intel")

	resp, err := (&http.Client{Transport: ssrfSafeTransport}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var payload struct {
		Items []struct {
			Title     string `json:"title"`
			HTMLURL   string `json:"html_url"`
			CreatedAt string `json:"created_at"`
		} `json:"items"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&payload); err != nil {
		return nil
	}

	var items []IntelItem
	for _, r := range payload.Items {
		date := ""
		if len(r.CreatedAt) >= 10 {
			date = r.CreatedAt[:10]
		}
		items = append(items, IntelItem{
			Source: "GitHub",
			Date:   date,
			Title:  r.Title,
			URL:    r.HTMLURL,
		})
	}
	return items
}

func fetchHNIntel(ctx context.Context) []IntelItem {
	const endpoint = "https://hn.algolia.com/api/v1/search" +
		"?query=openclaw+security&tags=story&hitsPerPage=5"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "anvil-scanner/security-intel")

	resp, err := (&http.Client{Transport: ssrfSafeTransport}).Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var payload struct {
		Hits []struct {
			Title       string `json:"title"`
			ObjectID    string `json:"objectID"`
			CreatedAt   string `json:"created_at"`
			StoryURL    string `json:"story_url"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&payload); err != nil {
		return nil
	}

	var items []IntelItem
	for _, h := range payload.Hits {
		if h.Title == "" {
			continue
		}
		date := ""
		if len(h.CreatedAt) >= 10 {
			date = h.CreatedAt[:10]
		}
		u := h.StoryURL
		if u == "" {
			u = fmt.Sprintf("https://news.ycombinator.com/item?id=%s", h.ObjectID)
		}
		items = append(items, IntelItem{
			Source: "HackerNews",
			Date:   date,
			Title:  h.Title,
			URL:    u,
		})
	}
	return items
}
