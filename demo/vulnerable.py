"""DEMO FILE — INTENTIONALLY VULNERABLE. DO NOT USE IN PRODUCTION.

This is the vulnerable target for the VulnBounty Studio demo: a tiny
"command runner" for a shop's admin page that passes user input straight
to eval(). That is a critical remote-code-execution flaw: anyone who can
reach the endpoint can run arbitrary Python on the server, including
os.system() calls.

The matching safe version is demo/secure.py, which does the same job
with ast.literal_eval and an allow-list of operations.
"""
import os


def run_command(cmd):
    """Run a shop admin command. INTENDED FLAW: eval() on user input."""
    return eval(cmd)


if __name__ == "__main__":
    # Attacker-controlled input reaches eval() with no check at all.
    user_input = input("admin command> ")
    print(run_command(user_input))
    # Example exploit (do not run against a real server):
    #   __import__('os').system('id')
    #   __import__('os').system('cat /etc/passwd')
