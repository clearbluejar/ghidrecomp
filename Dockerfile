# From https://github.com/clearbluejar/ghidra-python
FROM ghcr.io/clearbluejar/ghidra-python:latest

ENV GHIDRA_INSTALL_DIR=/ghidra

USER vscode
WORKDIR /home/vscode/

# install latest from pip
RUN pip install ghidrecomp

# point absolute ghidriffs dir to user
# this supports absoulte mapping "docker run --rm -it -v ${PWD}/ghidriffs:/ghidriffs ghidriff /bin/cat1 /bin/cat2"
RUN ln -s /ghidrecomps /home/vscode/

ENTRYPOINT ["/home/vscode/.local/bin/ghidrecomp"]

