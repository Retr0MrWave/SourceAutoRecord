#pragma once

#include "Utils/Memory.hpp"
#include "Utils/Platform.hpp"

#include <cstdint>
#include <cstring>
#include <vector>

// Inline hook: redirects calls to `func` to `hook` via a JMP written over
// the start of `func`. Detours call the original function like so:
//
//     hook.Disable();
//     auto ret = original(...);
//     hook.Enable();
//
// On Windows, the JMP is installed once through MinHook and points at a
// small per-hook gate, which checks `enabled` and jumps either to the
// detour or to MinHook's trampoline of the original function. Enable and
// Disable then only flip that flag and never write to game code. This
// matters: code writes are very slow under x86 translators like Rosetta 2
// (they invalidate the translated code), and some hooked functions run
// many times per frame. Elsewhere, Enable and Disable write and restore
// the JMP directly.
class Hook {
public:
	template <typename T = void *>
	Hook(T hook)
		: hook((void *)hook) {
		Hook::GetHooks().push_back(this);
	}

	~Hook() {}

	template <typename T = void *>
	void SetFunc(T func, bool enable = true) {
		this->Install((void *)func, enable);
	}

	void Enable();
	void Disable(bool lock = false);

	static void DisableAll() {
		for (Hook *h : Hook::GetHooks()) {
			h->Disable(true);
		}
	}

	static std::vector<Hook*> &GetHooks() {
		static std::vector<Hook *> hooks;
		return hooks;
	}

private:
	void Install(void *func, bool enable);
#ifdef _WIN32
	bool InstallGate();
#endif

	void *func = nullptr;
	void *hook;
	// Read directly by the gate on Windows, so it must stay a single byte
	// outside of executable memory
	volatile bool enabled = false;
	bool locked = false;
	uint8_t origCode[5];
#ifdef _WIN32
	// Set when installed through MinHook; otherwise the JMP is toggled
	void *trampoline = nullptr;
#endif
};
