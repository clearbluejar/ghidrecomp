# Create local venv
python3 -m venv .env
source .env/bin/activate

# update pip
pip install --upgrade pip

# Download latest pyi typings
pip install ghidra-stubs

# Install pyhdira
pip install pyhidra