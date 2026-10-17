"""
tool-judge — a permission layer that knows what your project is.

Two halves that must not be confused:

    rails    deterministic, enforces. Refuses.
    goalfit  a model, advises. Annotates.

`rails` is the wall. `goalfit` is the label on the door.
"""

from .rails import Checker, Decision, Pattern, Rail, Verdict
from .spec import Spec, SpecError, load, merge

__all__ = ["Checker", "Decision", "Pattern", "Rail", "Verdict",
           "Spec", "SpecError", "load", "merge"]
__version__ = "0.1.0"
