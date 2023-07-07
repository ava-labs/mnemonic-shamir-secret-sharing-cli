# Copyright (C) 2023, Ava Labs, Inc. All rights reserved.
# See the file LICENSE for licensing terms.

CXX := clang++
CXX_FLAGS := -std=c++17 -g -fno-omit-frame-pointer -Wall
LIB_INSTALL_DIR ?=
USR_INCLUDE ?= $(LIB_INSTALL_DIR)/usr/local/include
USR_LIB ?= $(LIB_INSTALL_DIR)/usr/local/lib

INCLUDE_PATHS := $(addprefix -I,$(shell find ./ -type d))

LIBRARIES := -L$(USR_LIB) -lcrypto

BUILD_DIRECTORY := build

APP_CPP_FILES += $(shell find ./ -type f -name '*.cpp')
APP_CPP_OBJECTS := $(addprefix $(BUILD_DIRECTORY)/,$(APP_CPP_FILES:.cpp=.o))
APP_TARGET := mnemonic-sss


.PHONY: all
all: $(BUILD_DIRECTORY)/$(APP_TARGET)

$(BUILD_DIRECTORY)/%.o : %.cpp
	@mkdir -p $(dir $@)
	@$(CXX) $(CXX_FLAGS) $(APP_FLAGS) -c $< $(INCLUDE_PATHS) -o $@
	@echo "CXX  <=  $<"

$(BUILD_DIRECTORY)/$(APP_TARGET) : $(APP_CPP_OBJECTS)
	@mkdir -p $(dir $@)
	@$(CXX) $(CXX_FLAGS) $(INCLUDE_PATHS) -o $@ $(APP_CPP_OBJECTS) $(LIBRARIES)
	@echo "Done. Built $@"

.PHONY: clean

clean:
	@rm -rf $(BUILD_DIRECTORY)

