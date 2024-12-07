# Makefile for End-to-End Execution of Circom Circuits

# Variables
CIRCUITS ?= verify_genoa_cert_1 verify_genoa_cert_2 verify_genoa_cert_3 verify_genoa_report
CURRENT_DIR = $(shell pwd)
CIRCUIT_DIR ?= $(CURRENT_DIR)/circuits
INPUT_DIR ?= $(CURRENT_DIR)/../samples
BUILD_DIR ?= $(CURRENT_DIR)/build
TRUSTED_SETUP_FILE ?= $(BUILD_DIR)/power_of_tau.ptau
INPUT_FILES ?= $(foreach circuit,$(CIRCUITS),$(BUILD_DIR)/input_$(circuit).json)

#Global Variables
export NODE_OPTIONS=--max_old_space_size=65536

# Default target
.DEFAULT_GOAL := all

# Phony targets
.PHONY: all prepare trusted_setup compile_circuits prepare_input generate_proofs generate_witness verify_proofs clean

# Main target
all: prepare verify_proofs

prepare:
	@echo "======================================"
	@echo "Installing third party libraries"
	@echo "======================================"
	npm install
	git submodule update

# Trusted Setup
trusted_setup: $(TRUSTED_SETUP_FILE)

$(TRUSTED_SETUP_FILE):
	@echo "======================================"
	@echo "Generating Trusted Setup (Powers of Tau)..."
	@echo "======================================"
	mkdir -p $(BUILD_DIR)
	snarkjs powersoftau new bn128 22 $(BUILD_DIR)/pot22_0000.ptau -v
	snarkjs powersoftau contribute $(BUILD_DIR)/pot22_0000.ptau $(BUILD_DIR)/pot22_0001.ptau --name="First Contribution" -v
	snarkjs powersoftau prepare phase2 $(BUILD_DIR)/pot22_0001.ptau $(TRUSTED_SETUP_FILE) -v

# Compile Circuits and Generate Keys
compile_circuits: $(foreach circuit,$(CIRCUITS),$(BUILD_DIR)/$(circuit)_circuit/verification_key.json)

$(BUILD_DIR)/%_circuit/verification_key.json: $(BUILD_DIR)/%_circuit/final.zkey
	@echo "Exporting verification key for $*..."
	snarkjs zkey export verificationkey $(BUILD_DIR)/$*_circuit/final.zkey $@

$(BUILD_DIR)/%_circuit/final.zkey: $(BUILD_DIR)/%_circuit/%.r1cs $(TRUSTED_SETUP_FILE)
	@echo "Generating proving key for $*..."
	snarkjs groth16 setup $(BUILD_DIR)/$*_circuit/$*.r1cs $(TRUSTED_SETUP_FILE) $(BUILD_DIR)/$*_circuit/final.zkey

$(BUILD_DIR)/%_circuit/%.r1cs $(BUILD_DIR)/%_circuit/%_js/%.wasm: $(CIRCUIT_DIR)/%.circom | $(BUILD_DIR)/%_circuit
	@echo "Compiling circuit $*.circom..."
	circom $< --r1cs --wasm --sym -l lib -l node_modules -o $(BUILD_DIR)/$*_circuit

# adjust heap limit before compilation
$(BUILD_DIR)/%_circuit:
	mkdir -p $@

# Prepare Input Files
prepare_input: $(INPUT_FILES)

$(INPUT_FILES): $(INPUT_DIR)/vcek.pem $(INPUT_DIR)/report.bin
	@echo "======================================"
	@echo "Preparing input files using Rust script..."
	@echo "======================================"
	cd tool && cargo run -r -- --arch genoa prepare-input --vcek-path $(INPUT_DIR)/vcek.pem --report-path $(INPUT_DIR)/report.bin --output $(BUILD_DIR)
	@touch $(INPUT_FILES)

# Generate Witnesses and Proofs
generate_witness: $(foreach circuit,$(CIRCUITS),$(BUILD_DIR)/$(circuit)_circuit/witness.wtns)

define WITNESS_RULE
$(BUILD_DIR)/$(1)_circuit/witness.wtns: $(BUILD_DIR)/$(1)_circuit/$(1)_js/$(1).wasm $(BUILD_DIR)/input_$(1).json
	@echo "Generating witness for $(1)..."
	node $(BUILD_DIR)/$(1)_circuit/$(1)_js/generate_witness.js $$< $(BUILD_DIR)/input_$(1).json $$@
endef

$(foreach circuit,$(CIRCUITS),$(eval $(call WITNESS_RULE,$(circuit))))

generate_proofs: $(foreach circuit,$(CIRCUITS),$(BUILD_DIR)/$(circuit)_circuit/proof.json)

define PROOF_RULE
$(BUILD_DIR)/$(1)_circuit/proof.json: $(BUILD_DIR)/$(1)_circuit/witness.wtns $(BUILD_DIR)/$(1)_circuit/final.zkey
	@echo "Generating proof for $(1)..."
	snarkjs groth16 prove $(BUILD_DIR)/$(1)_circuit/final.zkey $(BUILD_DIR)/$(1)_circuit/witness.wtns $$@ $(BUILD_DIR)/$(1)_circuit/public.json
endef

$(foreach circuit,$(CIRCUITS),$(eval $(call PROOF_RULE,$(circuit))))

# Verify Proofs
verify_proofs: $(foreach circuit,$(CIRCUITS),verify_$(circuit))

verify_%: $(BUILD_DIR)/%_circuit/proof.json $(BUILD_DIR)/%_circuit/verification_key.json $(BUILD_DIR)/%_circuit/public.json
	@echo "Verifying proof for $*..."
	snarkjs groth16 verify $(BUILD_DIR)/$*_circuit/verification_key.json $(BUILD_DIR)/$*_circuit/public.json $(BUILD_DIR)/$*_circuit/proof.json
	@echo "Proof verified for $*!"

# Clean Build Directory
clean:
	rm -rf $(BUILD_DIR)
