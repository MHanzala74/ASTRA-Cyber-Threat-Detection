import os
import tempfile
import warnings

warnings.filterwarnings("ignore")

# Must be set before `app` is imported (settings are read at import time).
_tmp = tempfile.mkdtemp(prefix="astra_test_")
os.environ["LOGGING_MODE"] = "merkle"
os.environ["MERKLE_BATCH_SIZE"] = "3"
os.environ["MERKLE_STORE_PATH"] = os.path.join(_tmp, "journal.jsonl")
os.environ["LOG_LEVEL"] = "WARNING"
