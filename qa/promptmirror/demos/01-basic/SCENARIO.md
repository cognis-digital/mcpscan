# Demo 01 — Indirect prompt injection in a retrieved document

## Scenario

You run a RAG assistant. Before stuffing a retrieved web page or document into
the model's context, you scan it with PROMPTMIRROR to catch **indirect prompt
injection** — hostile instructions hidden inside otherwise-benign content.

The file `retrieved_email.txt` is a support email that was fetched and is about
to be summarized by an LLM agent. It looks normal at the top, but an attacker
has embedded instructions further down trying to:

- override the assistant's prior instructions,
- extract the system prompt,
- exfiltrate data to an external address, and
- smuggle a hidden instruction using invisible Unicode characters.

## Run it

```bash
# Human-readable table
python -m promptmirror scan demos/01-basic/retrieved_email.txt

# Machine-readable JSON for a pipeline / CI gate
python -m promptmirror scan demos/01-basic/retrieved_email.txt --format json --fail-on high
echo "exit code: $?"   # non-zero because HIGH-severity findings exist

# Scan untrusted text straight from stdin before it reaches the model
cat demos/01-basic/retrieved_email.txt | python -m promptmirror scan -
```

## Expected result

Multiple findings, including HIGH-severity `instruction-override`,
`system-prompt-leak`, `data-exfiltration`, and `hidden-text` (invisible Unicode)
categories. Because there are HIGH findings and `--fail-on high` is the default,
the process exits with code `1` — your pipeline should refuse to feed this text
to the model unmodified.
