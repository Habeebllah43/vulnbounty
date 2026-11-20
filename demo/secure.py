"""DEMO FILE — THE SAFE VERSION of demo/vulnerable.py.

Same feature (a tiny calculator-style admin command), written safely:
user input is parsed with ast.literal_eval, which only allows Python
literals (numbers, strings, lists, dicts) and never executes code, and
the small expression evaluator below only permits arithmetic on numbers
— no names, no attribute access, no function calls, no imports.

A VulnBounty report claiming "RCE via eval()" against THIS file should
triage as invalid (valid=false, severity_score=0): there is no eval(),
no exec(), and no way for input to reach code execution.
"""
import ast
import operator

_ALLOWED_OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.Mod: operator.mod,
    ast.USub: operator.neg,
}


def _eval_node(node):
    """Evaluate one AST node. Only numbers and arithmetic are allowed."""
    if isinstance(node, ast.Expression):
        return _eval_node(node.body)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    if isinstance(node, ast.BinOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](
            _eval_node(node.left), _eval_node(node.right)
        )
    if isinstance(node, ast.UnaryOp) and type(node.op) in _ALLOWED_OPS:
        return _ALLOWED_OPS[type(node.op)](_eval_node(node.operand))
    raise ValueError("unsupported expression")


def run_command(cmd):
    """Evaluate a simple arithmetic command. No eval, no exec, no names."""
    tree = ast.parse(cmd, mode="eval")
    return _eval_node(tree)


def parse_literal(text):
    """Parse user-supplied data (config, prices) as a literal only."""
    return ast.literal_eval(text)


if __name__ == "__main__":
    user_input = input("admin command> ")
    try:
        print(run_command(user_input))
    except Exception as e:
        print("rejected:", e)
