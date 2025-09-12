import sys

missing_packages = []
try:
    import pefile
except ImportError:
    missing_packages.append("pefile")

try:
    import lief
except ImportError:
    missing_packages.append("lief")

try:
    import capstone
except ImportError:
    missing_packages.append("capstone")

try:
    import unicorn
except ImportError:
    missing_packages.append("unicorn")

if missing_packages:
    print("Missing packages:", ",".join(missing_packages))
else:
    print("All required packages are installed.")
