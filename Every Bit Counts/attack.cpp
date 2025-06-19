#include <iostream>
#include <fstream>
#include <string>

#include <triton/context.hpp>
#include <triton/x86Specifications.hpp>
#include <LIEF/LIEF.hpp>
#include <capstone/capstone.h>

constexpr uint64_t target_addr = 0x4035C2;
constexpr uint64_t miss_addr   = 0x4035E0;

int main() {
	std::string path = "C:\\Users\\90965\\Desktop\\计协CTF\\Reverse\\2、每一位都至关重要\\分析\\every_bit_counts";
	if (path == "") {
		std::cout << "path is empty." << std::endl;
		exit(0);
	}

	std::unique_ptr<const LIEF::ELF::Binary> bin{};
	if (!(bin = LIEF::ELF::Parser::parse(path))) {
		std::cout << "open file failed." << std::endl;
		exit(0);
	}
	auto funcdata = bin->get_content_from_virtual_address(0x004003E2, 0x3219);

	triton::Context ctx(triton::arch::architecture_e::ARCH_X86_64);
	triton::ast::SharedAstContext astx = ctx.getAstContext();

	csh md{};
	cs_open(CS_ARCH_X86, CS_MODE_64, &md);
	ctx.setAstRepresentationMode(triton::ast::representations::SMT_REPRESENTATION);
	const uint64_t begin_addr = 0x4003E2, end_addr = 0x4035FB;
	cs_insn* insn = nullptr;
	size_t count = cs_disasm(md, funcdata.data(), funcdata.size(), begin_addr, 0, &insn);
	if (count <= 0) {
		std::cout << "disasm failed." << std::endl;
		exit(0);
	}

	uint32_t argc = 2;
	ctx.setConcreteRegisterValue(ctx.registers.x86_rdi, argc);

	constexpr uint64_t argv_addr = 0x0000001912340000;
	constexpr uint64_t argv_param_addr1 = 0x0000002912340000;
	constexpr uint64_t argv_param_addr2 = 0x0000002912640000;

	std::string argv_param1 = "./every_bit_counts";
	std::string argv_param2 = "....................................................";
	ctx.setConcreteMemoryAreaValue(argv_param_addr1, argv_param1.data(), argv_param1.size());
	ctx.setConcreteMemoryAreaValue(argv_param_addr2, argv_param2.data(), argv_param2.size());
	
	ctx.setConcreteMemoryAreaValue(argv_addr + 0x0, &argv_param_addr1, sizeof(uint64_t));
	ctx.setConcreteMemoryAreaValue(argv_addr + 0x8, &argv_param_addr2, sizeof(uint64_t));

	ctx.setConcreteRegisterValue(ctx.registers.x86_rsi, argv_addr);

	ctx.symbolizeMemory(argv_param_addr2, argv_param2.size()); // 对flag字符串内存进行符号化

	for (size_t i = 0; i < count; i++) {
		triton::arch::Instruction ins(insn[i].address, insn[i].bytes, insn[i].size);
		ctx.disassembly(ins);

		if (ins.getAddress() >= 0x400401 && ins.getAddress() <= 0x40042C) {
			continue;
		}
		if (ins.getAddress() >= 0x400456 && ins.getAddress() <= 0x400481) {
			continue;
		}

		if (ins.getAddress() == 0x400447) {
			ctx.setConcreteRegisterValue(ctx.registers.x86_rax, (uint64_t)0x34);
			std::cout << ins.getDisassembly() << "    pass(set rax: 0x34)" << std::endl;
			continue;
		}
		
		if (ins.getAddress() == 0x400486) {
			ctx.clearPathConstraints(); // 在开始前清理之前收集的路径谓词
		}
		if (ins.getAddress() == target_addr) {
			std::vector<triton::ast::SharedAbstractNode> real_constraints;

			auto& pathconstraints = ctx.getPathConstraints();
			for (auto& constraint : pathconstraints) {
				if (!constraint.isMultipleBranches()) { continue; }
				bool is_we_want = false;
				for (auto& branch : constraint.getBranchConstraints()) {
					uint64_t dst = std::get<2>(branch);
					if (dst == miss_addr) { // 证明是我们想要的分支路径
						is_we_want = true;
						break;
					}
				}
				if (!is_we_want) { continue; }
				for (auto& branch : constraint.getBranchConstraints()) {
					uint64_t dst = std::get<2>(branch);
					if (dst == miss_addr) { continue; }
					real_constraints.push_back(std::get<3>(branch));
				}
			}

			while (real_constraints.size() > 1) { // 合成所有路径谓词
				triton::ast::SharedAbstractNode a = real_constraints.back();
				real_constraints.pop_back();
				triton::ast::SharedAbstractNode b = real_constraints.back();
				real_constraints.pop_back();
				real_constraints.push_back(astx->land(a, b));
			}
			
			auto model = ctx.getModel(real_constraints.back()); // 求解约束
			
			std::string flag = "";
			flag.resize(0x34);
			for (auto& item : model) {
				flag[item.first] = (uint8_t)item.second.getValue();
			}

			std::cout << std::endl << "flag: " << flag << std::endl;
			break;
		}


		ctx.processing(ins);
		std::cout << ins.getDisassembly() << std::endl;
	}

	cs_free(insn, count);
	cs_close(&md);
	return 0;
}