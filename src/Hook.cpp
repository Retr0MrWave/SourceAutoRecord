#include "Hook.hpp"

#include "Modules/Console.hpp"

#include <cstring>

#ifdef _WIN32
// cmp byte ptr [enabled], 0 (7) + je trampoline (6) + jmp detour (5)
#	define GATE_SIZE 18
#	define GATE_STRIDE 32
#	define GATE_PAGE_SIZE 0x1000

// Gates get their own executable page, so flipping a hook's flag never
// writes to executable memory. They are never freed, since a detour may
// still be running through one while SAR unloads.
static uint8_t *AllocGate() {
	static uint8_t *page = nullptr;
	static size_t used = 0;
	if (!page || used + GATE_STRIDE > GATE_PAGE_SIZE) {
		page = (uint8_t *)VirtualAlloc(nullptr, GATE_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		used = 0;
		if (!page) return nullptr;
	}
	uint8_t *gate = page + used;
	used += GATE_STRIDE;
	return gate;
}

static void WriteGate(uint8_t *gate, volatile bool *enabled, void *trampoline, void *detour) {
	// cmp byte ptr [enabled], 0
	gate[0] = 0x80;
	gate[1] = 0x3D;
	*(uint32_t *)(gate + 2) = (uintptr_t)enabled;
	gate[6] = 0x00;
	// je trampoline
	gate[7] = 0x0F;
	gate[8] = 0x84;
	*(uint32_t *)(gate + 9) = (uintptr_t)trampoline - ((uintptr_t)gate + 13);
	// jmp detour
	gate[13] = 0xE9;
	*(uint32_t *)(gate + 14) = (uintptr_t)detour - ((uintptr_t)gate + GATE_SIZE);
	FlushInstructionCache(GetCurrentProcess(), gate, GATE_SIZE);
}

static void WarnLegacy(void *func, MH_STATUS status) {
	if (console && console->DevWarning) {
		console->DevWarning("Hook %p: MinHook failed (%s), using legacy toggle hook\n", func, MH_StatusToString(status));
	}
}

bool Hook::InstallGate() {
	static MH_STATUS initStatus = MH_Initialize();
	if (initStatus != MH_OK && initStatus != MH_ERROR_ALREADY_INITIALIZED) {
		WarnLegacy(this->func, initStatus);
		return false;
	}

	uint8_t *gate = AllocGate();
	if (!gate) {
		WarnLegacy(this->func, MH_ERROR_MEMORY_ALLOC);
		return false;
	}

	void *trampoline;
	MH_STATUS status = MH_CreateHook(this->func, gate, &trampoline);
	if (status != MH_OK) {
		WarnLegacy(this->func, status);
		return false;
	}

	// The gate needs the trampoline address, so it can only be written now
	WriteGate(gate, &this->enabled, trampoline, this->hook);

	status = MH_EnableHook(this->func);
	if (status != MH_OK) {
		MH_RemoveHook(this->func);
		WarnLegacy(this->func, status);
		return false;
	}

	this->trampoline = trampoline;
	return true;
}
#endif

void Hook::Install(void *func, bool enable) {
	if (func != this->func) {
		// Put the previous function back first
		this->Disable();
#ifdef _WIN32
		if (this->trampoline) {
			MH_DisableHook(this->func);
			this->trampoline = nullptr;
		}
#endif
		this->func = func;
		if (func) {
#ifdef _WIN32
			bool gated = this->InstallGate();
#else
			bool gated = false;
#endif
			if (!gated) Memory::UnProtect(func, 5);
		}
	}
	if (enable) this->Enable();
}

void Hook::Enable() {
	if (this->locked) return;
	if (this->enabled) return;
	if (!this->func || !this->hook) return;
#ifdef _WIN32
	if (this->trampoline) {
		this->enabled = true;
		return;
	}
#endif
	memcpy(this->origCode, this->func, sizeof this->origCode);
	uint8_t *ptr = (uint8_t *)this->func;
	ptr[0] = 0xE9;  // JMP
	*(uint32_t *)(ptr + 1) = (uintptr_t)this->hook - ((uintptr_t)ptr + 5);
	this->enabled = true;
}

void Hook::Disable(bool lock) {
#ifdef _WIN32
	if (this->trampoline) {
		this->enabled = false;
		if (lock && !this->locked) {
			this->locked = true;
			// SAR is unloading, and the gate jumps into its detour, so put
			// the original code back. The trampoline stays valid for any
			// detour that is still running.
			MH_DisableHook(this->func);
		}
		return;
	}
#endif
	if (lock) this->locked = true;
	if (!this->enabled) return;
	if (!this->func || !this->hook) return;
	memcpy(this->func, this->origCode, sizeof this->origCode);
	this->enabled = false;
}
