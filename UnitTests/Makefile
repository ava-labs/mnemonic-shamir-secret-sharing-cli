# Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
# See the file LICENSE for licensing terms.

CXX := clang++-10
CXX_FLAGS := -std=c++17 -g -fno-omit-frame-pointer -Wall
LIB_INSTALL_DIR ?=
USR_INCLUDE ?= $(LIB_INSTALL_DIR)/usr/local/include
USR_LIB ?= $(LIB_INSTALL_DIR)/usr/local/lib

APP_ROOT ?= ../MnemonicShamirCLI
APP_DIRECTORIES := $(addprefix -I,$(shell find $(APP_ROOT)/ -type d))

GOOGLE_TEST_LIB := gtest
GOOGLE_MOCK_LIB := gmock
GOOGLE_TEST_INCLUDE ?= /usr/local/include

INCLUDE_PATHS := $(APP_DIRECTORIES) -I$(GOOGLE_TEST_INCLUDE) $(addprefix -I,$(shell find ./ -type d))

APP_CPP_OBJECTS := $(shell find $(APP_ROOT)/build/ -type f -name '*.o')

# Don't include the cpp file that defines the main function.
APP_CPP_OBJECTS := $(patsubst $(APP_ROOT)/build/main.o, , $(APP_CPP_OBJECTS))

LIBRARIES := -l$(GOOGLE_TEST_LIB) -l$(GOOGLE_MOCK_LIB) $(APP_CPP_OBJECTS) -L$(USR_LIB) -lcrypto -lpthread 

BUILD_DIRECTORY := build

UNIT_TEST_CPP_FILES := $(shell find ./ -type f -name '*.cpp')
UNIT_TEST_CPP_OBJECTS := $(addprefix $(BUILD_DIRECTORY)/,$(UNIT_TEST_CPP_FILES:.cpp=.o))
TEST_TARGET := unit_tests


.PHONY: all
all: $(BUILD_DIRECTORY)/$(TEST_TARGET)

$(BUILD_DIRECTORY)/%.o : %.cpp
	@mkdir -p $(dir $@)
	@$(CXX) $(CXX_FLAGS) $(INCLUDE_PATHS) -c $< -o $@ 
	@echo "CXX  <=  $<"

$(BUILD_DIRECTORY)/$(TEST_TARGET) : $(UNIT_TEST_CPP_OBJECTS)
	@mkdir -p $(dir $@)
	@$(CXX) $(CXX_FLAGS) $(INCLUDE_PATHS) -o $@ $(UNIT_TEST_CPP_OBJECTS) $(LIBRARIES) 
	@echo "Done. Built $@"

.PHONY: clean

clean:
	@rm -rf $(BUILD_DIRECTORY)
