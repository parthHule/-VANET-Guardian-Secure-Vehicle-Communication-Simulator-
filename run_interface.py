#!/usr/bin/env python3

import streamlit.web.cli as stcli
import sys
from pathlib import Path

if __name__ == "__main__":
    # Add the project root to Python path
    project_root = Path(__file__).parent
    if str(project_root) not in sys.path:
        sys.path.append(str(project_root))
    
    # Set up the interface path
    interface_path = project_root / "src" / "interface" / "app.py"
    sys.argv = ["streamlit", "run", str(interface_path), "--server.port=8501"]
    sys.exit(stcli.main()) 