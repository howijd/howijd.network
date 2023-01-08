# That's our default target when none is given on the command line

CDT_BUILD_OUTPUT = ./build

# Get Version information
CDT_VERSION_FULL 								:= $(shell git describe --match "v*" --always --tags)
cdt_version_full_parts 					:= $(subst -, ,$(CDT_VERSION_FULL))
CDT_VERSION_TAG        					:= $(word 1,$(cdt_version_full_parts))
CDT_VERSION_COMMITS_SINCE_TAG  	:= $(word 2,$(cdt_version_full_parts))
CDT_VERSION_COMMIT_SHORT  			:= $(word 3,$(cdt_version_full_parts))
CDT_VERSION_COMMIT_LONG 	 			:= $(shell git rev-parse HEAD)
CDT_VERSION            					:= $(subst v,,$(CDT_VERSION_TAG))
cdt_version_parts      					:= $(subst ., ,$(CDT_VERSION))
CDT_VERSION_MAJOR              	:= $(word 1,$(cdt_version_parts))
CDT_VERSION_MINOR              	:= $(word 2,$(cdt_version_parts))
CDT_VERSION_PATCH              	:= $(word 3,$(cdt_version_parts))

# If CDT_BUILD_VERBOSE equals 0 then the above command will be hidden.
# If CDT_BUILD_VERBOSE equals 1 then the above command is displayed.
# If CDT_BUILD_VERBOSE equals 2 then give the reason why each target is rebuilt.
CDT_BUILD_VERBOSE = 2

ifeq ($(filter undefine,$(.FEATURES)),)
$(error GNU Make >= 3.82 is required. Your Make version is $(MAKE_VERSION))
endif

# That's our default target when none is given on the command line
PHONY := help
help:
	@echo  'BINARIES:'
	@echo  '  bin 			- build all binaries'
	@echo  '  bin-rust	  	- build rust cli tool'
	@echo  '  bin-go	  	- build go cli tool'
	@echo  ''
	@echo  'LIBRARIES:'
	@echo  '  lib-rust	  	- build rust library'
	@echo  ''
	@echo  'TESTS:'
	@echo  '  rust		  	- build rust cli tool'
	@echo  ''
	@echo  'GENERAL:'
	@echo  '  clean		  	- Remove most generated files but keep the config and'
	@echo  '            	       	  enough build support to build external modules'
	@echo  '  version	  	- print verision info which would be used by build'
	@echo  ''

# Avoid interference with shell env settings
unexport GREP_OPTIONS

# If the user is running make -s (silent mode), suppress echoing of
# commands
# make-4.0 (and later) keep single letter options in the 1st word of MAKEFLAGS.
silence:=$(findstring s,$(filter-out --%,$(MAKEFLAGS)))

ifeq ($(silence),s)
CDT_BUILD_VERBOSE = 0
endif

export CDT_BUILD_VERBOSE

ifneq ($(CDT_BUILD_OUTPUT),)
# Make's built-in functions such as $(abspath ...), $(realpath ...) cannot
# expand a shell special character '~'. We use a somewhat tedious way here.
CDT_BUILD_DIR := $(shell mkdir -p $(CDT_BUILD_OUTPUT)/{bin,lib} && cd $(CDT_BUILD_OUTPUT) && pwd)
$(if $(CDT_BUILD_DIR),, \
     $(error failed to create output directory "$(CDT_BUILD_OUTPUT)"))
# $(realpath ...) resolves symlinks
CDT_BUILD_DIR := $(realpath $(CDT_BUILD_DIR))
else
CDT_BUILD_DIR := $(CURDIR)
endif # ifneq ($(CDTBUILD_OUTPUT),)

CDT_BUILD_LIB_DIR = $(CDT_BUILD_DIR)/lib
CDT_BUILD_BIN_DIR = $(CDT_BUILD_DIR)/bin

CDT_RUST_LIB = $(CDT_BUILD_LIB_DIR)/libcryptdatum.rlib

this-makefile := $(lastword $(MAKEFILE_LIST))
CDT_SRC_DIR := $(realpath $(dir $(this-makefile)))
CDT_CMD_DIR := $(CDT_SRC_DIR)/cmd

ifneq ($(words $(subst :, ,$(CDT_SRC_DIR))), 1)
$(error source directory cannot contain spaces or colons)
endif

# Do not print "Entering directory ...",
# but we want to display it when entering to the output directory
# so that IDEs/editors are able to understand relative filenames.
MAKEFLAGS += --no-print-directory

PHONY += clean
clean:
	rm -rf $(CDT_BUILD_DIR)

PHONY += bin-rust
bin-rust: lib-rust
	@rustc $(CDT_CMD_DIR)/cryptdatum.rs \
		--extern cryptdatum=$(CDT_RUST_LIB) \
		--edition 2021 \
		--crate-type bin \
		-C debuginfo=0 \
		-C opt-level=3 \
		-o $(CDT_BUILD_BIN_DIR)/cryptdatum-rust

PHONY += bin-go
bin-go:
	@go build -o $(CDT_BUILD_BIN_DIR)/cryptdatum-go $(CDT_CMD_DIR)/cryptdatum.go

bin-c:
	@gcc -o $(CDT_BUILD_BIN_DIR)/cryptdatum-c \
		$(CDT_CMD_DIR)/cryptdatum.c \
		cryptdatum.c

# build all binaries and deps
PHONY += bin-all
bin: bin-rust bin-go bin-c

PHONY += env
env:
	$(foreach VAR,$(sort $(filter CDT_%,$(.VARIABLES))),$(info $(VAR) is $($(VAR))))

PHONY += lib-rust
lib-rust:
	@rustc $(CDT_SRC_DIR)/cryptdatum.rs \
		--crate-type=lib \
		-C debuginfo=0 \
		-C opt-level=3 \
		-o $(CDT_RUST_LIB)

PHONY += version
version:
	@echo  'CDT_VERSION_FULL: 		${CDT_VERSION_FULL}'
	@echo  'CDT_VERSION_TAG: 		${CDT_VERSION_TAG}'
	@echo  'CDT_VERSION: 			${CDT_VERSION}'
	@echo  'CDT_VERSION_MAJOR: 		${CDT_VERSION_MAJOR}'
	@echo  'CDT_VERSION_MINOR: 		${CDT_VERSION_MINOR}'
	@echo  'CDT_VERSION_PATCH: 		${CDT_VERSION_PATCH}'
	@echo  'CDT_VERSION_COMMITS_SINCE_TAG: 	${CDT_VERSION_COMMITS_SINCE_TAG}'
	@echo  'CDT_VERSION_COMMIT_SHORT: 	${CDT_VERSION_COMMIT_SHORT}'
	@echo  'CDT_VERSION_COMMIT_LONG: 	${CDT_VERSION_COMMIT_LONG}'

PHONY += FORCE
FORCE:

# Declare the contents of the PHONY variable as phony.  We keep that
# information in a variable so we can use it in if_changed and friends.
.PHONY: $(PHONY)
