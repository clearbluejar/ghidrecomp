# Create local venv
python3 -m venv .env
source .env/bin/activate

# upgrade pip
pip install --upgrade pip

# Download latest pyi typings for Ghidra Version
pip install ghidra-stubs

# If linux arm64 os, need to build native binaries for Ghidra
# If arm64 os, need to build native binaries for Ghidra
if uname -a | grep -q 'aarch64'; then
    if [ -e $GHIDRA_INSTALL_DIR/support/buildNatives ]
    then
        $GHIDRA_INSTALL_DIR/support/buildNatives
    else
        # needed for Ghidra 11.2+
        pushd $GHIDRA_INSTALL_DIR/support/gradle/
        gradle buildNatives
        popd
    fi
fi

# install local workspace and test requirements
pip install -e ".[testing]"