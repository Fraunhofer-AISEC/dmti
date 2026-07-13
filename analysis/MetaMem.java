//Generates Meta-Information of a provided binary about Heap and Stack Variables 
//@author Andreas Hager, andreas.hager@aisec.fraunhofer.de
//@category Analysis
//@keybinding
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.LocalVariableImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.TreeMap;
import java.util.stream.Collectors;

import javax.xml.crypto.Data;

/**
 * @author Andreas Hager
 * 
 *         Runnable Class MetaMem implements the Metadata extraction of Memory
 *         Operations. It generates Metadata for Heap and Stack operations
 *
 */
public class MetaMem extends GhidraScript {
	private static final Boolean MERGE_VARIABLES = false;
	private static final Boolean IGNORE_PARAMS = false;
	private static final Boolean MERGE_PARAMS = false;
	private static final Boolean CACLULATE_SIZE = false;
	private static final String OUT_FILE_EXTENSION = ".json";
	private static final String LR = "X30";
	private static final String BP = "x29";
	private static final String SP = "sp";
	private static final String BUF = "buf";
	private static final String LIBC_START = "__libc_start_main";
	private static final String QUIET_FLAG = "-v";
	private static final List<String> functionsToIgnore = Arrays.asList("_init", "_start", "_INIT_0", "_fini",
			"_FINI_0", "entry", "__libc_csu_init", "__libc_csu_fini", "deregister_tm_clones", "register_tm_clones",
			"__do_global_dtors_aux", "frame_dummy", "__gmon_start__", "call_weak_fn",
			"decodeHexChars", "decodeHexWChars", "my_memcpy", "my_memmove", "my_strcpy", "my_strncpy");
	private static final List<String> branches = Arrays.asList("BRANCH", "BRANCHIND", "CBRANCH", "CALL", "CALLIND",
			"CALLOTHER");

	private boolean verbose = false;

	@Override
	public void run() throws Exception {
		long start = System.currentTimeMillis();
		// Set flags from arguments
		setFlags();

		setAnalysisOption(currentProgram, "Stack", "true");
		setAnalysisOption(currentProgram, "Function ID", "true");
		setAnalysisOption(currentProgram, "Decompiler Parameter ID", "true");

		// Get External Symbols
		final List<String> symbolsToIgnore = getSymbolsToIgnore();
		// Get functions to Instrument
		final List<Function> functionsToInstrument = getFunctionsToInstrument(symbolsToIgnore);
		// Get instrumentation Data
		final Map<String, Pair<Function, List<CodeBlock>>> instrumentationData = getInstrumentationData(
				functionsToInstrument);
		// Serialize
		final String serializedData = serializeData(instrumentationData);
		// Write to file
		final String target = getProgramFile().getAbsolutePath() + OUT_FILE_EXTENSION;
		try (final FileWriter writer = new FileWriter(target)) {
			writer.write(serializedData + System.lineSeparator());
		}
		final Set<PosixFilePermission> perms = new HashSet<>();
		perms.add(PosixFilePermission.OWNER_READ);
		perms.add(PosixFilePermission.GROUP_READ);
		perms.add(PosixFilePermission.OTHERS_READ);
		perms.add(PosixFilePermission.OWNER_WRITE);
		Files.setPosixFilePermissions(Path.of(target), perms);
		// print(serializedData + "\n");

		long finish = System.currentTimeMillis();
		long timeElapsed = finish - start;
		long seconds = timeElapsed / 1000;
		long milis = timeElapsed - seconds;
		println("INFO: Execution took " + timeElapsed / 1000 + "." + milis + "s");
	}

	private Optional<Address> getMain() {
		final Listing lst = currentProgram.getListing();
		final FunctionManager fm = currentProgram.getFunctionManager();
		final Set<Address> libCMainRefAddress = new HashSet<Address>();

		for (final Function fun : fm.getFunctions(true)) {
			if (fun.getName().equals(LIBC_START)) {
				for (final Reference libCMainRefs : getReferencesTo(fun.getEntryPoint())) {

					// all functions referencing libc_start, in best case only entry function
					libCMainRefAddress.add(libCMainRefs.getFromAddress());
				}
			}

		}
		if (libCMainRefAddress.isEmpty()) {
			println("No libc_start_main found, exit");
			return Optional.empty();
		}

		List<Function> entryFunctions = getGlobalFunctions("_start");
		if (entryFunctions.size() > 1) {
			println("There are more entrypoints !");
			// return Optional.empty();
		} else if (entryFunctions.size() < 1) {
			println("There are no entrypoints !");
			return Optional.empty();
		}
		final Function entryFun = entryFunctions.get(0);

		// another way to find libc_start_main, xref Address vs. call Address
		final InstructionIterator instrIter = lst.getInstructions(entryFun.getBody(), true);
		Address libCMainAddress = null;

		for (Instruction instr : instrIter) {
			if (instr.getFlowType().isCall()) {
				libCMainAddress = instr.getFlows()[0];
				if (lst.getFunctionAt(libCMainAddress).getName().equals(LIBC_START)) {
					break;
				}

			}
		}

		// try to get lib_start address
		Address mainAddress = libCMainAddress; // if there is no main candidate we stay at libc_start_main
		final DecompInterface decompInterface = new DecompInterface();
		decompInterface.openProgram(currentProgram);
		final DecompileResults decompResults = decompInterface.decompileFunction(entryFun, 60, monitor);
		if (!decompResults.decompileCompleted())
			throw new IllegalStateException();
		final HighFunction highFunction = decompResults.getHighFunction();

		Iterator<PcodeOpAST> pCodes = highFunction.getPcodeOps();
		while (pCodes.hasNext()) {
			final PcodeOpAST instruction = pCodes.next();
			// two types of call instructions in p-code
			if (instruction.getOpcode() == PcodeOp.CALLIND || instruction.getOpcode() == PcodeOp.CALL) {
				final Varnode libCMainNode = instruction.getInput(0);

				if (!libCMainNode.isUnique() || libCMainNode.getDef() == null) {
					// CALL, direct address for libcMain

					// compare Xrefs of libc_start_main and direkt address for a valid
					// libc_start_main address
					if (libCMainRefAddress.contains(libCMainNode.getAddress())
							|| libCMainNode.getAddress().equals(libCMainAddress)) {
						// we found libCMaind Varnode

						// first parameter must point
						if (instruction.getInput(1).isInput()) {
							// do arm stuff
							final Address mainPointerAddress = instruction.getInput(1).getAddress();

							// ARM
							if (lst.getDataAt(mainPointerAddress).isPointer()) {
								mainAddress = (Address) lst.getDataAt(mainPointerAddress).getValue();
							}
						} else {
							// MIPS
							mainAddress = getFirstParamAddress(instruction.getInput(1));
						}
					}
				} else {

					// indirekt CALLIND of x64
					PcodeOp libCMainRef = libCMainNode.getDef();
					for (Varnode vn : libCMainRef.getInputs()) {
						if (libCMainRefAddress.contains(vn.getAddress())) {
							// found libcVarnode
							// find first parameter
							mainAddress = getFirstParamAddress(instruction.getInput(1));
						}
					}

				}

			}
		}
		assert mainAddress != null;
		return Optional.of(mainAddress);
	}

	private Address getFirstParamAddress(Varnode firstArgument) {
		final PcodeOp pcOp = firstArgument.getDef();
		Address returnValue = null;
		switch (pcOp.getOpcode()) {
			case PcodeOp.PTRSUB:
				returnValue = toAddr(pcOp.getInput(1).getAddress().getOffset());
				// returnValue = toAddr(pcOp.getInput(1).getOffset());
				break;
			case PcodeOp.PTRADD:
				break;
			default:
		}
		return returnValue;
	}

	private List<Address> getAddressesContainingReferences(final MemoryBlock memBlock) {
		final List<Address> addresses = new LinkedList<>();

		for (Address addr = memBlock.getStart(); memBlock.contains(addr); addr = addr.next()) {
			final List<Reference> refs = Arrays.asList(getReferencesTo(addr));
			refs.remove(null);
			if (!refs.isEmpty()) {
				addresses.add(addr);
			}
		}
		return addresses;
	}

	private void setFlags() {
		final List<String> args = Arrays.asList(getScriptArgs());
		if (args.contains(QUIET_FLAG)) {
			verbose = false;
		}
	}

	/**
	 * Get all External Symbols to ignore from the symbol.
	 * 
	 * @return the Symbols to ignore
	 */
	private List<String> getSymbolsToIgnore() {
		final List<String> symbolsToIgnore = new LinkedList<>();
		final SymbolTable symTab = currentProgram.getSymbolTable();
		final SymbolIterator symIter = symTab.getExternalSymbols();
		for (Symbol sym = symIter.next(); symIter.hasNext(); sym = symIter.next()) {
			final String symName = sym.getName();
			symbolsToIgnore.add(symName);

			if (verbose) {
				println("Symbol: " + symName);
			}
		}
		return symbolsToIgnore;
	}

	/**
	 * Get all functions to instrument (allFunctions - symbolsToIgnore -
	 * functionsToIgnore)
	 * 
	 * @param symbolsToIgnore the function to ignore
	 * @return the function to insturment
	 */
	private List<Function> getFunctionsToInstrument(final List<String> symbolsToIgnore) {
		final List<Function> functionsToInstrument = new LinkedList<>();
		for (final Function fun : getAllFunctions()) {
			final String funName = fun.getName();
			if (functionsToIgnore.contains(funName)) {
				if (verbose) {
					println("IGNORE Function: " + funName);
				}
			} else if (symbolsToIgnore.contains(funName)) {
				if (verbose) {
					println("IGNORE Symbol: " + funName);
				}
			} else {
				if (verbose) {
					final AddressSetView body = fun.getBody();
					final Address startAddr = body.getMinAddress();
					final Address endAddr = body.getMaxAddress();
					println("Function: " + funName + ", starts at: " + startAddr.getOffset() + ", and ends at: "
							+ endAddr.getOffset());
				}
				// addVariables(fun);
				functionsToInstrument.add(fun);
			}
		}
		return functionsToInstrument;
	}

	private List<Function> getAllFunctions() {
		final List<Function> functions = new LinkedList<>();
		Function fun = getFirstFunction(); // erste Funktion
		while (fun != null && !monitor.isCancelled()) { // Schleife über alle Funktionen
			functions.add(fun);
			fun = getFunctionAfter(fun); // next
		}
		return functions;
	}

	private Map<String, Pair<Function, List<CodeBlock>>> getInstrumentationData(
			final List<Function> functionsToInstrument) throws CancelledException {
		final Map<String, Pair<Function, List<CodeBlock>>> instrumentationData = new TreeMap<>();

		for (final Function function : functionsToInstrument) {
			final List<CodeBlock> bbs = new LinkedList<>();
			for (final CodeBlock bb : new BasicBlockModel(function.getProgram())
					.getCodeBlocksContaining(function.getBody(), monitor)) {
				bbs.add(bb);
			}
			instrumentationData.put(function.getName(), new Pair<>(function, bbs));
		}
		return instrumentationData;
	}

	private Boolean isOpReg(final Instruction inst, final int index, final String reg) {
		final List<Object> operandRepresentation = inst.getDefaultOperandRepresentationList(index);
		for (final Object representation : operandRepresentation) { // (x29)
			if (reg.equalsIgnoreCase(representation.toString())) {
				return true;
			}
		}
		return false;
	}

	private Boolean containsReg(final Instruction inst, final String reg) {
		Boolean found = false;
		for (int i = 0; i < inst.getNumOperands(); i++) {
			if (isOpReg(inst, i, reg)) {
				found = true;
			}
		}
		return found;
	}

	private Boolean isWritingSPBPLR(final Instruction inst) {
		return inst.getNumOperands() > 0 && (isOpReg(inst, 0, SP) || isOpReg(inst, 0, BP) || isOpReg(inst, 0, LR));
	}

	private Boolean containsOffset(final Instruction inst, final int ghidraOffset, final int varSize,
			final int stackSize) {
		Boolean offsetFound = false;
		boolean containsSP = containsReg(inst, SP);
		boolean containsBP = containsReg(inst, BP);
		if (isWritingSPBPLR(inst)) {
			if (verbose) {
				println("SP/BP/LR target found: " + inst);
			}
			return false;
		}

		final PcodeOp[] codes = inst.getPcode();
		final boolean isMove = codes.length == 1 && codes[0].getMnemonic().equals("COPY")
				&& codes[0].getNumInputs() == 1;
		final boolean isSPMove = isMove && containsSP && Math.abs(ghidraOffset) == 0;
		final boolean isBPMove = isMove && containsBP && stackSize - Math.abs(ghidraOffset) == 0;
		if (isSPMove || isBPMove) {
			if (verbose) {
				println("BP/SP Move found: " + inst);
			}
			return true;
		}

		for (int i = 0; i < inst.getNumOperands(); i++) {
			final List<Object> operandRepresentation = inst.getDefaultOperandRepresentationList(i);
			for (final Object representation : operandRepresentation) {
				final String repStr = representation.toString();
				if (repStr != null && repStr.length() > 0) {
					try {
						final int repInt = Integer.decode(repStr);
						final int absRepInt = Math.abs(repInt);
						if (verbose) {
							println("    " + inst + ", Found offset: " + absRepInt + ", ghidra offset: "
									+ Math.abs(ghidraOffset) + ", contains SP: " + containsSP);
						}

						boolean isSPRelativeAccess = containsSP && absRepInt >= Math.abs(ghidraOffset)
								&& absRepInt < Math.abs(ghidraOffset) + varSize;
						boolean isBPRelativeAccess = containsBP && absRepInt >= stackSize - Math.abs(ghidraOffset)
								&& absRepInt < stackSize - Math.abs(ghidraOffset) + varSize;

						if (isSPRelativeAccess || isBPRelativeAccess) {
							if (verbose) {
								println("    Offset Match whith ghidra: " + ghidraOffset);
							}
							offsetFound = true;
						}
					} catch (NumberFormatException e) {
						if (verbose) {
							println("ERROR: cannot parse: " + repStr + ", as Int");
						}
					}
				}
			}
		}

		return offsetFound;
	}

	private Boolean containsDeref(final Instruction inst) {
		Boolean found = false;
		for (int i = 0; i < inst.getNumOperands(); i++) {
			final List<Object> operandRepresentation = inst.getDefaultOperandRepresentationList(i);
			for (final Object representation : operandRepresentation) {
				final String rep = representation.toString();
				if ("[".equalsIgnoreCase(rep) || "]".equalsIgnoreCase(rep)) {
					found = true;
				}
			}
		}
		return found;
	}

	private Boolean containsAccess(final Function fun, final Instruction first, final Instruction inst,
			int ghidraOffset, int size) {
		int stackSize = fun.getStackFrame().getFrameSize();
		boolean containsAccess = false;
		for (final Variable var : fun.getAllVariables()) {

			int prologLen = 4;
			if (first.getPcode()[0].getOpcode() == PcodeOp.INT_SUB) {
				prologLen += 4;
			}
			boolean isProlog = fun.getBody().getMinAddress().add(prologLen).compareTo(inst.getAddress()) >= 0;
			if (verbose && isProlog) {
				println("Instr " + inst + " is prolog");
			}

			boolean isEpilog = fun.getBody().getMaxAddress().subtract(7).compareTo(inst.getAddress()) <= 0;
			if (verbose && isEpilog) {
				println("Instr " + inst + " is epilog");
			}
			boolean containsSP = containsReg(inst, SP);
			boolean containsBP = containsReg(inst, BP);
			boolean containsOffset = var.isStackVariable() && containsOffset(inst, ghidraOffset, size, stackSize);

			if (containsOffset && (containsSP || containsBP) && !isProlog && !isEpilog) {
				containsAccess = true;
			}
		}
		return containsAccess;
	}

	private Pair<List<Instruction>, List<Instruction>> getVariableAccess(final Function function,
			final Variable variable, final int varSize) {
		final List<Instruction> instructions = new LinkedList<>();
		final List<Instruction> ptrs = new LinkedList<>();
		int stackSize = function.getStackFrame().getFrameSize();
		int ghidraOffset = stackSize;
		try {
			ghidraOffset += variable.getStackOffset();
		} catch (UnsupportedOperationException e) {
			println("Storage does not have a stack varnode");
		}
		if (verbose) {
			print("Function: " + function.getName() + ", Variable: " + variable.getName() + ", Stack Size: "
					+ stackSize);
			if (variable.isStackVariable()) {
				print(", Var Offset: " + variable.getStackOffset());
				print(", Ghidra Offset: " + ghidraOffset);
			}
			print("\n");
		}

		final Listing listing = currentProgram.getListing();
		final InstructionIterator instIter = listing.getInstructions(function.getBody(), true);
		final Instruction first = instIter.next();
		for (Instruction inst = first; instIter.hasNext() && !monitor.isCancelled(); inst = instIter.next()) {

			if (containsAccess(function, first, inst, ghidraOffset, varSize)) {
				boolean containsDeref = containsDeref(inst);
				if (containsDeref) {
					if (verbose) {
						println("  Access Found in " + inst.getAddressString(false, false) + " " + inst);
					}
					ptrs.add(inst);
				} else {
					if (verbose) {
						println("  Access To Instrument Found in " + inst);
					}
					instructions.add(inst);
				}
			} else {
				if (verbose) {
					println("  No offset found in inst: " + inst);
				}
			}
		}
		return new Pair<>(instructions, ptrs);
	}

	private String serializeData(final Map<String, Pair<Function, List<CodeBlock>>> instrumentationData) {
		return "{" + serializeMetaData() + ", " + serializeGlobals() + ", " + serializeFunctions(instrumentationData)
				+ "}";
	}

	private String serializeMetaData() {
		// Get Main
		Optional<Address> optMain = getMain();
		if (optMain.isEmpty()) {
			throw new IllegalStateException("Unable to find main!");
		}
		Address main = optMain.get();
		if (verbose) {
			println("Main address: " + main);
		}
		final Map<String, String> metaData = currentProgram.getMetadata();
		String outStr = "\"meta_data\": {" + "\"main_address\": \"" + main + "\"";

		for (Map.Entry<String, String> data : metaData.entrySet()) {
			outStr += ", \"" + data.getKey() + "\": \"" + data.getValue() + "\"";
		}
		if (verbose) {
			outStr += ", " + serializeMemoryBlocks();
		}
		return outStr + "}";
	}

	private String serializeGlobals() {
		String outStr = "\"global_variables\": [";
		// List globals
		final Memory memory = currentProgram.getMemory();
		final List<Pair<String, List<Address>>> allNameAndAddrs = Arrays.asList(
				// ".rodata", // constante globale variablen
				".data", // initialisierte globale Variablen (statische vars)
				".bss" // uninitialisierte globale Variablen
		).stream().map(bname -> new Pair<>(bname, getAddressesContainingReferences(memory.getBlock(bname))))
				.collect(Collectors.toList());

		boolean isFirst = true;
		for (final Pair<String, List<Address>> nameAndAddrs : allNameAndAddrs) {
			final String memBlockName = nameAndAddrs.getFirst();
			final List<Address> addrs = nameAndAddrs.getSecond();
			final int addrsCount = addrs.size();
			for (int i = 0; i < addrsCount; i++) {
				final Address addr = addrs.get(i);

				if (!memory.getBlock(memBlockName).getStart().equals(addr) && Arrays.asList(getReferencesTo(addr))
						.stream().map(ref -> getInstructionContaining(ref.getFromAddress()))
						.filter(inst -> inst != null).toArray().length > 0) {
					final Address nextAddr = i == addrsCount - 1 ? memory.getBlock(memBlockName).getEnd().add(1L)
							: addrs.get(i + 1);
					final long size = nextAddr.subtract(addr);

					if (!isFirst) {
						outStr += ", ";
					} else {
						isFirst = false;
					}
					outStr += "{\"address\": \"" + addr + "\"" + ", \"size\": \"" + size + "\""
							+ ", \"memory_block\": \"" + memBlockName + "\"" + ", \"references\": [";
					boolean isFirstRef = true;
					for (final Reference ref : getReferencesTo(addr)) {
						final Instruction inst = getInstructionContaining(ref.getFromAddress());
						if (inst != null) {
							if (!isFirstRef) {
								outStr += ", ";
							} else {
								isFirstRef = false;
							}
							Address address = ref.getFromAddress();
							if (containsDeref(inst)) {
								address = address.subtract(4);
							}
							outStr += "\"" + address + "\"";

						}
					}
					outStr += "]}";
				}
			}
		}
		return outStr + "]";
	}

	private String serializeMemoryBlocks() {
		final Memory memory = currentProgram.getMemory();
		final List<MemoryBlock> memBlocks = Arrays.asList(memory.getBlocks());
		boolean isFirst = true;
		String outStr = "\"memory_blocks\": [";
		for (final MemoryBlock memBlock : memBlocks) {
			if (!isFirst) {
				outStr += ", ";
			} else {
				isFirst = false;
			}
			outStr += "{\"block_name\": \"" + memBlock.getName() + "\"" + ", \"size\": \"" + memBlock.getSize() + "\""
					+ ", \"start\": \"" + memBlock.getStart() + "\"" + ", \"end\": \"" + memBlock.getEnd() + "\"}";
		}
		return outStr + "]";
	}

	private String serializeFunctions(final Map<String, Pair<Function, List<CodeBlock>>> instrumentationData) {
		String outStr = "\"functions\": [";
		boolean isFirst = true;
		for (final Entry<String, Pair<Function, List<CodeBlock>>> data : instrumentationData.entrySet()) {
			final Function fun = data.getValue().getFirst();
			final List<CodeBlock> bbs = data.getValue().getSecond();

			final String memBlockName = currentProgram.getMemory().getBlock(fun.getBody().getMinAddress()).getName();

			if (verbose) {
				println("Function: " + fun.getName());
			}

			if (".text".equals(memBlockName) && fun.getAllVariables().length > 0) {
				if (!isFirst) {
					outStr += ", ";
				} else {
					isFirst = false;
				}
				outStr += serializeFunction(fun, bbs);
			}
		}
		outStr += "]";
		return outStr;
	}

	private String serializeFunction(final Function fun, final List<CodeBlock> bbs) {
		final Address funStartAddress = fun.getBody().getMinAddress();
		final Address funEndAddress = fun.getBody().getMaxAddress();

		int prolog_len = 2;

		InstructionIterator instIter = currentProgram.getListing().getInstructions(bbs.get(0).getMinAddress(), true);
		Instruction inst = instIter.next();
		inst = inst.getNext().getNext();
		while (inst != null && inst.getNumOperands() > 0 && (isOpReg(inst, 0, SP) || isOpReg(inst, 0, BP))) {
			prolog_len++;
			inst = inst.getNext();
		}

		int epilog_len = 2;

		instIter = currentProgram.getListing().getInstructions(bbs.get(bbs.size() - 1).getMaxAddress(), true);
		inst = inst.getPrevious().getPrevious();
		while (inst != null && inst.getNumOperands() > 0 && (isOpReg(inst, 0, SP) || isOpReg(inst, 0, BP))) {
			epilog_len++;
			inst = inst.getPrevious();
		}

		final Variable firstVar = fun.getAllVariables()[0];
		if (verbose) {
			println("Function: " + fun.getName() + ", Stack Size: " + fun.getStackFrame().getFrameSize());
		}
		int stackSize = ((fun.getStackFrame().getFrameSize() - 1) / 16) * 16;
		if (verbose) {
			println("Stack Purge Size: " + (0xFFffFFff - fun.getStackPurgeSize()));
		}

		return "{\"function_name\": \"" + fun.getName() + "\"" + ", \"calling_convention\": \""
				+ fun.getCallingConventionName() + "\"" + ", \"start_address\": \"" + funStartAddress + "\""
				+ ", \"end_address\": \"" + funEndAddress + "\"" + ", \"stack_size\": \"" + stackSize + "\""
				+ ", \"prolog_len\": \"" + prolog_len + "\""
				+ ", \"epilog_len\": \"" + epilog_len + "\""
				+ ", " + serializeVariables(fun, Arrays.asList(fun.getAllVariables())) + ", " + serializeBBs(bbs) + "}";
	}

	private String serializeVariables(final Function fun, final List<Variable> vars) {
		String outStr = "\"variables\": [";
		boolean isFirstParam = true;
		for (int i = vars.size() - 1; i >= 0; i--) {
			Variable var = vars.get(i);
			final StackFrame sf = fun.getStackFrame();
			while (var != null && i > 0 && !var.isStackVariable()) {
				i--;
				var = vars.get(i);
			}
			while (IGNORE_PARAMS && var != null && i > 0
					&& (sf.growsNegative() && var.getMinAddress().toString().contains("Stack[-")
							|| (!sf.growsNegative() && var.getMinAddress().toString().contains("Stack[0x")))) {
				i--;
				var = vars.get(i);
			}
			if (!isFirstParam) {
				outStr += ", ";
			} else {
				isFirstParam = false;
			}

			final int frameSize = fun.getStackFrame().getFrameSize();
			int stackOffset = frameSize + 8;
			int nextStackOffset = frameSize;
			try {
				stackOffset += var.getStackOffset();
				nextStackOffset += var.getStackOffset();
			} catch (UnsupportedOperationException e) {
				println("Storage does not have a stack varnode");
			}

			if (i > 0) {
				Variable next = vars.get(i - 1);
				while (next != null && i > 1 && !next.isStackVariable()) {
					i--;
					next = vars.get(i - 1);
				}
				// Merge variables
				while (MERGE_VARIABLES && next != null && i > 2 && next.getName().contains(BUF)) {
					i--;
					next = vars.get(i - 1);
				}
				while (MERGE_PARAMS && var != null && i > 2
						&& (sf.growsNegative() && var.getMinAddress().toString().contains("Stack[0x")
								|| (!sf.growsNegative() && var.getMinAddress().toString().contains("Stack[-")))) {
					i--;
					next = vars.get(i - 1);
				}

				nextStackOffset = frameSize;
				try {
					nextStackOffset += next.getStackOffset();
				} catch (UnsupportedOperationException e) {
					println("Storage does not have a stack varnode");
				}
			}

			int size;
			if (CACLULATE_SIZE) {
				size = Math.abs(nextStackOffset - stackOffset);
			} else {
				size = var.getVariableStorage().size();
			}
			outStr += serializeVariable(fun, var, size);
		}
		return outStr + "]";
	}

	private String serializeVariable(final Function fun, final Variable var, int size) {

		int stackOffset = 0;
		if (var.isStackVariable()) {
			stackOffset += fun.getStackFrame().getFrameSize();
			try {
				stackOffset += var.getStackOffset();
			} catch (UnsupportedOperationException e) {
				println("Storage does not have a stack varnode");
			}
		}

		String outStr = "{\"variable_name\": \"" + var.getName() + "\"" + ", \"data_type\": \"" + ""
				+ "\"" + ", \"min_address\": \"" + var.getMinAddress() + "\"" + ", \"first_use_offset\": \""
				+ var.getFirstUseOffset() + "\"" // relative to function entry point
				+ ", \"storage\": \"" + var.getVariableStorage() + "\"" + ", \"size\": \"" + size + "\""
				+ ", \"is_stack_variable\": \"" + var.isStackVariable() + "\"" + ", \"is_memory_variable\": \""
				+ var.isMemoryVariable() + "\"" + ", \"is_register_variable\": \"" + var.isRegisterVariable() + "\""
				+ ", \"is_valid\": \"" + var.isValid() + "\"" + ", \"stack_offset\": \"" + stackOffset + "\""
				+ ", \"references\": [";
		boolean isFirstInst = true;

		final Pair<List<Instruction>, List<Instruction>> instsAndPtrs = getVariableAccess(fun, var, size); // accessInstsAndPtrs.getSecond()
		for (final Instruction inst : instsAndPtrs.getFirst()) {
			if (!isFirstInst) {
				outStr += ", ";
			} else {
				isFirstInst = false;
			}
			outStr += "\"" + inst.getAddressString(false, false) + "\"";
		}

		outStr += "], \"ptrs\": [";
		isFirstInst = true;
		for (final Instruction inst : instsAndPtrs.getSecond()) {
			if (!isFirstInst) {
				outStr += ", ";
			} else {
				isFirstInst = false;
			}
			outStr += "\"" + inst.getAddressString(false, false) + "\"";
		}
		outStr += "]";

		final List<Register> associatedRegisters = var.getRegisters();
		if (associatedRegisters != null) {
			outStr += ", \"associated_registers\": [";
			boolean isFirstReg = true;
			for (final Register reg : associatedRegisters) {
				if (!isFirstReg) {
					outStr += ", ";
				} else {
					isFirstReg = false;
				}

				outStr += "\"" + reg.getName() + "\"";
			}
			outStr += "]";
		}

		return outStr + "}";
	}

	private List<Address> getBranches(final CodeBlock bb) {
		final List<Address> result = new LinkedList<>();
		final Listing listing = currentProgram.getListing();
		final InstructionIterator instIter = listing.getInstructions(bb.getMinAddress(), true);

		for (final Instruction inst : instIter) {
			if (inst.getMaxAddress().compareTo(bb.getMaxAddress()) < 0) {
				final List<PcodeOp> pcode = Arrays.asList(inst.getPcode());

				for (final PcodeOp pc : pcode) {
					if (verbose) {
						println("pcodeops: " + pc.getMnemonic());
					}
					if (branches.contains(pc.getMnemonic())) {
						result.add(inst.getMinAddress());
					}
				}
			}
		}
		return result;
	}

	private String serializeBBs(final List<CodeBlock> bbs) {
		String outStr = "\"basic_blocks\": [";
		boolean isFirstBB = true;
		for (final CodeBlock bb : bbs) {
			if (!isFirstBB) {
				outStr += ", ";
			} else {
				isFirstBB = false;
			}

			outStr += "{\"bb_name\": \"" + bb.getName() + "\"" + ", \"start_address\": \"" + bb.getMinAddress() + "\"";
			for (final Address addr : getBranches(bb)) {
				outStr += ", \"end_address\": \"" + addr.add(3) + "\"}, " + "{\"bb_name\": \"" + addr.add(4) + "\""
						+ ", \"start_address\": \"" + addr.add(4) + "\"";
			}
			outStr += ", \"end_address\": \"" + bb.getMaxAddress() + "\"}";
		}
		return outStr + "]";
	}
}

/**
 * @author Andreas Hager
 *
 * @param <T>
 * @param <U>
 */
class Pair<T, U> {
	private final T first;
	private final U second;

	public Pair(final T first, final U second) {
		if (first == null || second == null) {
			throw new NullPointerException("The first and the second element of a Pair should not be null!");
		}
		this.first = first;
		this.second = second;
	}

	public T getFirst() {
		return this.first;
	}

	public U getSecond() {
		return this.second;
	}

	@Override
	public int hashCode() {
		return Objects.hash(first, second);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (!(obj instanceof Pair)) {
			return false;
		}
		Pair other = (Pair) obj;
		return Objects.equals(first, other.first) && Objects.equals(second, other.second);
	}

	@Override
	public String toString() {
		return "Pair [first=" + first + ", second=" + second + "]";
	}
}
