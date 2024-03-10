#!/usr/bin/env python3

# This file provides Claude with both the control_compat.c and control.c files,
# both of which are necessary to identify CVE-2023-0266.
#
# sean@heelan.io

import os
import sys

from anthropic import Anthropic
from dotenv import load_dotenv

load_dotenv()

client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))
chat_mode = len(sys.argv) > 1 and sys.argv[1] == "--chat"

with open("res/control_compat.c") as fd:
    control_compat_file = fd.readlines()

with open("res/control.c") as fd:
    control_file = fd.readlines()

query = f"""
You are an expert that audits C source code in the Linux kernel for security vulnerabilities.
You are assisting a software developer.
You will be careful and diligent when checking software for security vulnerabilities.
You will use precise technical language when describing security vulnerabilities that you find.
When you find a security vulnerability you will describe step by step and in detail the root cause of the vulnerability and how it may be triggered by an attacker.

Here is the source code for the sound/core/control.c and sound/core/control_compat.c files from the Linux kernel.
They are inside tags that look like <source></source>.
Check the code for concurrency related vulnerabilities.
Ensure that locks are used appropriately and that no race conditions occur.
You must check every path leading to each function to ensure locks are used appropriately.

sound/core/control.c
<source>
{control_file}
</source>

sound/core/control_compat.c
<source>
{control_compat_file}
</source>
"""

messages = [
    {
        "role": "user",
        "content": query,
    }
]

message = client.messages.create(
    max_tokens=4096,
    messages=messages,
    model="claude-3-opus-20240229",
)

for line in message.content[0].text.split("\n"):
    print(line)

if not chat_mode:
    sys.exit(0)

while True:
    messages.append({"role": message.role, "content": message.content})
    user_input = input("chat> ")
    messages.append({"role": "user", "content": user_input})

    message = client.messages.create(
        max_tokens=4096,
        messages=messages,
        model="claude-3-opus-20240229",
    )

    for line in message.content[0].text.split("\n"):
        print(line)
