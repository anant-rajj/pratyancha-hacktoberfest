# HACKATHON.md

## Team name
pratyancha

## Team members
- Anant Raj
- Anshul Pandey
- Vinayak Agrawal
- Amrit Sagar

## Problem statement
Problem 4: Published Package vs Source Code Integrity Analyzer

## Models we use and why
- qwen2.5-coder:7b (via local Ollama at `http://localhost:11434/api/generate`): Performs semantic diff verification on candidate source-to-build mappings (`src/*.ts` to `dist/*.js`), distinguishes benign bundler/transpiler output from supply-chain injections, and generates evidence-grounded plain-English security explanations with a deterministic static fallback when offline.
