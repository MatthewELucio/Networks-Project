#!/usr/bin/env python3
"""Generate structured representative prompt chains using an OpenAI LLM."""

from __future__ import annotations

import argparse
import json
import os
import random
import sys
import time
from pathlib import Path
from typing import Iterable

from openai import OpenAI, OpenAIError

CATEGORIES = [
    "coding from scratch",
    "coding assistance",
    "image generation",
    "questions",
    "conversations",
    "research explanation",
    "productivity planning",
    "debugging help",
    "data analysis",
    "creative writing",
]

OUTPUT_PATH = Path(__file__).resolve().parent / "prompt_bank.json"

SYSTEM_MESSAGE = (
    "You are a prompt engineer whose job is to enumerate realistic, logical prompt chains that a human would feed to a large language model. "
    "Every prompt should build on context when it makes sense, and the entire chain should feel like a single interaction (one-shot or few-shot). "
    "Strictly reply with a JSON array of prompt strings containing only the human (user) input side of each step—do not include assistant/model responses—so that downstream tools can ingest the collection without additional parsing."
)

REQUEST_TEMPLATE = (
    "Generate {count} prompts for a human-style interaction in the \"{category}\" category. "
    "The first prompt should introduce the goal, and subsequent prompts should naturally follow. "
    "Each prompt should be phrased as a user query or instruction; assume the assistant will respond, but do not include any assistant text in your response. "
    "Return exactly {count} distinct prompt strings encoded as a JSON array."
)


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a JSON bank of prompt chains by querying an OpenAI model repeatedly."
    )
    parser.add_argument(
        "count",
        type=int,
        help="Number of prompt chains (i.e., number of separate LLM queries) to generate.",
    )
    parser.add_argument(
        "--api-key",
        dest="api_key",
        help="OpenAI API key. Defaults to the OPENAI_API_KEY environment variable if omitted.",
    )
    parser.add_argument(
        "--max-chain-length",
        type=int,
        default=5,
        help="Maximum number of prompts within a single chain (default: %(default)s).",
    )
    parser.add_argument(
        "--model",
        default="gpt-4o-mini",
        help="OpenAI model to use for generation."
    )
    return parser.parse_args()


def backoff_sleep(attempt: int) -> None:
    time.sleep(min(60, 2 ** attempt))


def call_openai(client: OpenAI, messages: Iterable[dict], model: str) -> str:
    for attempt in range(5):
        try:
            resp = client.chat.completions.create(
                model=model,
                messages=list(messages),
                temperature=0.9,
                max_tokens=600,
            )
            return resp.choices[0].message.content
        except OpenAIError as exc:
            if attempt == 4 or not hasattr(exc, "code"):
                raise
            backoff_sleep(attempt)
    raise RuntimeError("Unable to contact OpenAI after multiple retries.")


def normalize_chain(raw_text: str) -> list[str]:
    def try_parse(text: str) -> list[str] | None:
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list) and all(isinstance(entry, str) for entry in parsed):
                return parsed
        except json.JSONDecodeError:
            return None
        return None

    parsed = try_parse(raw_text)
    if parsed is not None:
        return parsed

    start = raw_text.find("[")
    end = raw_text.rfind("]")
    if start != -1 and end != -1 and end > start:
        parsed = try_parse(raw_text[start : end + 1])
        if parsed is not None:
            return parsed

    lines = [line.strip() for line in raw_text.splitlines() if line.strip()]
    cleaned = []
    for line in lines:
        if line and not line.lower().startswith("[") and not line.lower().startswith("{"):
            if all(char in "[]{}.," for char in line):
                continue
            cleaned.append(line.lstrip("-0123456789. "))
    return cleaned


def build_messages(category: str, prompt_count: int) -> list[dict]:
    return [
        {"role": "system", "content": SYSTEM_MESSAGE},
        {"role": "user", "content": REQUEST_TEMPLATE.format(count=prompt_count, category=category)},
    ]


def load_prompt_bank(path: Path) -> list[dict]:
    if not path.exists():
        return []

    with path.open("r", encoding="utf-8") as reader:
        data = json.load(reader)

    if not isinstance(data, list):
        raise ValueError("Prompt bank must contain a list of prompt-chain entries.")

    return data


def main() -> None:
    args = parse_arguments()

    if args.count <= 0:
        raise SystemExit("count must be a positive integer")
    if args.max_chain_length <= 0:
        raise SystemExit("max-chain-length must be a positive integer")

    api_key = args.api_key or os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise SystemExit("An OpenAI API key must be provided via --api-key or OPENAI_API_KEY.")

    client = OpenAI(api_key=api_key)
    existing_bank = load_prompt_bank(OUTPUT_PATH)

    prompt_bank: list[dict] = []
    random.shuffle(CATEGORIES)

    for idx in range(args.count):
        category = CATEGORIES[idx % len(CATEGORIES)]
        chain_length = random.randint(1, args.max_chain_length)
        messages = build_messages(category, chain_length)
        print(f"Generating chain #{idx + 1}/{args.count} ({category}, {chain_length} prompts)", file=sys.stderr)
        raw_response = call_openai(client, messages, args.model)
        prompts = normalize_chain(raw_response)
        if len(prompts) < 1:
            raise RuntimeError(f"OpenAI returned no prompts for chain #{idx + 1}")

        prompt_bank.append(
            {
                "category": category,
                "model": args.model,
                "prompts": prompts,
                "chain_length": len(prompts),
            }
        )

    combined_bank = existing_bank + prompt_bank
    with OUTPUT_PATH.open("w", encoding="utf-8") as fout:
        json.dump(combined_bank, fout, indent=2)

    print(
        f"Appended {len(prompt_bank)} prompt chains (total {len(combined_bank)} saved) to {OUTPUT_PATH}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
