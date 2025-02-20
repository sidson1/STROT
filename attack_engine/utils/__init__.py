import importlib
import os.path
importlib


def load_exploit(exploit_name: str = "") -> object:

    return importlib.import_module(name="attack_engine.utils."+exploit_name)

