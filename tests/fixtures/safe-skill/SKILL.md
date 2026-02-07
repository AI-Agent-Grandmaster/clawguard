---
name: weather-checker
description: Check current weather conditions
metadata:
  openclaw:
    requires:
      env:
        - WEATHER_API_KEY
---

# Weather Checker

Get current weather for any location.

## Usage

Ask about the weather in any city:
- "What's the weather in Tokyo?"
- "Is it raining in London?"

## How it works

Uses the OpenWeather API to fetch current conditions.
Requires WEATHER_API_KEY environment variable.
