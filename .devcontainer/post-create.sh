# Create local venv
python3 -m venv .venv
source .venv/bin/activate

# upgrade pip
pip install --upgrade pip

# Download latest pyi typings for Ghidra Version
pip install ghidra-stubs

# If Ghidra major version is 11 (pre pyghidra 3.0), pin pyghidra==2.2.1
if [[ "$GHIDRA_VERSION" == 11.* ]]; then
    echo "Detected Ghidra $GHIDRA_VERSION, pinning pyghidra==2.2.1..."
    pip install -U "pyghidra==2.2.1"
fi

# If linux arm64 os, need to build native binaries for Ghidra
if uname -a | grep -q 'aarch64'; then
    if [ -e $GHIDRA_INSTALL_DIR/support/buildNatives ]
    then
        $GHIDRA_INSTALL_DIR/support/buildNatives
    else
        # needed for Ghidra 11.2+
        pushd "$GHIDRA_INSTALL_DIR/support/gradle/"
        gradle buildNatives
        popd
    fi
fi

# install local workspace and test requirements
pip install -e ".[sast,testing]"
