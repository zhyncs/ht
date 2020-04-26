CXX = g++
CXXFLAGS = -std=c++11 -fno-exceptions -fno-rtti -fno-omit-frame-pointer -O3 -DBUILD_VERSION=\"`git rev-parse HEAD`\"
LDFLAGS = -lcrypto
SRCDIR = src
OBJECTS = $(patsubst %.cc, %.o, $(wildcard $(SRCDIR)/*.cc))
TARGET = ht
$(TARGET) : $(OBJECTS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJECTS) $(LDFLAGS)
$(OBJECTS) : %.o : %.cc
	$(CXX) -c $(CXXFLAGS) $< -o $@
default : $(TARGET)
install : $(TARGET)
	install bin/$(TARGET) /usr/local/bin
cmake :
	mkdir build || true && cd build && cmake .. && make
format :
	clang-format -i $(SRCDIR)/*.cc $(SRCDIR)/*.h
lint :
	cpplint $(SRCDIR)/*.cc $(SRCDIR)/*.h
.PHONY : clean
clean :
	-rm -rf $(SRCDIR)/*.o $(TARGET) third_party/*.o build
