# Create local venv
python3 -m venv .env
source .env/bin/activate

# Download latest pyi typings
pip install ghidra-stubs

# Install ghidra-bridge
pip install ghidra_bridge

# Install bridge scripts to local dir
python -m ghidra_bridge.install_server .ghidra_bridge

# Install pyhdira
pip install pyhidra

# If arm64 os, need to build native binaries for Ghidra
if uname -a | grep -q 'aarch64'; then
    $GHIDRA_INSTALL_DIR/support/buildNatives
fi

# Setup Ghidra Dev for Reference
git clone git@github.com:NationalSecurityAgency/ghidra.git ~/ghidra-master
pushd ~/ghidra-master

# Follow setup from https://github.com/NationalSecurityAgency/ghidra/blob/master/DevGuide.md
gradle -I gradle/support/fetchDependencies.gradle init
gradle prepdev

popd

echo 'To open up a Ghidra latest dev: code ~/ghidra-master'