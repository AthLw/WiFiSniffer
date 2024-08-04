WorkDIR=$PWD

# install libtins and modify
git clone https://github.com/mfontanini/libtins && cd libtins && git checkout fe221866238282057478b3c15e985dd12c8f49ef && git apply "$WorkDIR/radiotap_he.patch" && mkdir build && cd build && cmake ../ && make && sudo make install && sudo ldconfig

# install jsoncpp
sudo apt install -y meson
cd "$WorkDIR"
git clone https://github.com/open-source-parsers/jsoncpp && cd jsoncpp && meson build && cd build && meson install

# install matplotlib
pip install matplotlib

