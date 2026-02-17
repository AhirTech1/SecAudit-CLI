"""Insecure pattern scanner.

Detects dangerous function calls (eval, new Function, child_process.exec),
missing security middleware, and unvalidated user input in JS/Node.js code.
"""
